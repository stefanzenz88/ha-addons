#!/usr/bin/env python3
"""Netz-RADIUS: FreeRADIUS für MAC-Authentifizierung (MAB) der Switch-Ports und WLAN-802.1X (WPA-Enterprise).
Freigegebene MACs kommen aus dem Home-Assistant-Geräteinventar (todo.netzwerk_gerate, abgehakt und nicht ⛔).
WLAN-Benutzer kommen aus der App-Konfiguration (PEAP-MSCHAPv2 / TTLS-PAP, eigenes Zertifikat).
Ergebnis jeder Anmeldung → Sensor sensor.netz_radius, Ablehnungen → Audit-Log (+ NAC-Freigabe-Push bei Switch-Ports)."""
import json, os, re, signal, subprocess, threading, time, urllib.request
from collections import deque
from datetime import datetime, timedelta

OPTF = os.environ.get('OPTIONS', '/data/options.json')
OPT = json.load(open(OPTF)) if os.path.exists(OPTF) else {}
RADDB = os.environ.get('RADDB', '/etc/raddb')
RADIUSD = os.environ.get('RADIUSD', 'radiusd')
RADIUSD_ARGS = os.environ.get('RADIUSD_ARGS', '').split()
TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')
HA = os.environ.get('HA_URL', 'http://supervisor/core')
SECRET = OPT.get('radius_secret') or ''
SWITCHES = dict(s.split('=', 1) if '=' in s else (s, s) for s in OPT.get('switches', []))
APS = dict(s.split('=', 1) if '=' in s else (s, s) for s in OPT.get('wlan_aps', []))
WLAN_SECRET = OPT.get('wlan_secret') or SECRET
MA_PFLICHT = bool(OPT.get('message_authenticator_pflicht', True))
NAME_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,31}$')
BENUTZER = [b for b in OPT.get('wlan_benutzer', []) if NAME_RE.match((b.get('name') or '').lower()) and b.get('passwort')]
CERTS = os.environ.get('CERTS', '/data/certs')
PROFIL_PORT = int(OPT.get('profil_port', 8098))
PROFIL_SSID = OPT.get('profil_ssid') or 'Zenz-Test'
SERVERNAME = 'radius.zenz.home'
SMTP = {k: OPT.get(k) or '' for k in ('smtp_server', 'smtp_benutzer', 'smtp_passwort', 'smtp_absender')}
SMTP_PORT = int(OPT.get('smtp_port') or 587)
GAST_STUNDEN = int(OPT.get('gast_kennwort_stunden') or 24)
PROFIL_URL = OPT.get('profil_url') or ''
TEMPF = os.environ.get('TEMPF', '/data/gast_kennwoerter.json')
SHARE = os.environ.get('SHARE', '/share/netz-radius')
SYNC = int(OPT.get('sync_sekunden', 60))
NAC_WEBHOOK = OPT.get('nac_webhook_url') or ''
AUDIT_URL = OPT.get('audit_url') or ''
MAC_RE = re.compile(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', re.I)
STATEF = os.environ.get('STATEF', '/data/radius_state.json')
LOCK = threading.Lock()
LETZTE = deque(maxlen=30)
try:
    ST = json.load(open(STATEF))
except Exception:
    ST = {'gemeldet': {}, 'ok': {}}

def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, flush=True)

def http(url, daten=None, auth=False, methode=None):
    h = {'Content-Type': 'application/json'}
    if auth:
        h['Authorization'] = 'Bearer ' + TOKEN
    req = urllib.request.Request(url, data=json.dumps(daten).encode() if daten is not None else None, headers=h, method=methode)
    with urllib.request.urlopen(req, timeout=15) as r:
        t = r.read()
    return json.loads(t) if t[:1] in (b'{', b'[') else None

def mac_norm(s):
    h = re.sub(r'[^0-9a-f]', '', s.lower())
    return ':'.join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ''

def varianten(mac):
    h = mac.replace(':', '').lower()
    p = [h[i:i + 2] for i in range(0, 12, 2)]
    v = {h, h.upper(), ':'.join(p), ':'.join(p).upper(), '-'.join(p), '-'.join(p).upper()}
    return sorted(v)

# ------------------------------------------------------------------ Konfiguration
def ma_modus():
    # BlastRADIUS-Schutz ab FreeRADIUS 3.2.5 automatisch, ältere Versionen kennen 'auto' nicht
    try:
        v = subprocess.run([RADIUSD, '-v'], capture_output=True, text=True).stdout
        m = re.search(r'Version (\d+)\.(\d+)\.(\d+)', v)
        if m and tuple(int(x) for x in m.groups()) >= (3, 2, 5):
            return 'auto'
    except Exception:
        pass
    return 'no'

def lesbar(pfad):
    # radiusd läuft als eigener Benutzer – Schlüssel/Kennwörter nur für dessen Gruppe lesbar
    for g in ('radius', 'freerad'):
        try:
            import shutil
            shutil.chown(pfad, group=g)
            os.chmod(pfad, 0o640)
            return
        except Exception:
            pass
    os.chmod(pfad, 0o644)

def kurzname(name, ip):
    return re.sub(r'[^A-Za-z0-9_-]', '', name) or ip.replace('.', '_')

def zertifikate():
    """Eigene CA (10 Jahre) + Server-Zertifikat (825 Tage, Apple-Grenze) – bleiben in /data erhalten."""
    os.makedirs(CERTS, exist_ok=True)
    def ossl(*a):
        subprocess.run(['openssl', *a], check=True, capture_output=True)
    if not os.path.exists(f'{CERTS}/ca.pem'):
        ossl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '3650', '-keyout', f'{CERTS}/ca.key', '-out', f'{CERTS}/ca.pem',
             '-subj', '/O=Netz Zenz/CN=Netz Zenz RADIUS CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        log('Neue RADIUS-CA erzeugt')
    neu = not os.path.exists(f'{CERTS}/server.pem')
    if not neu:
        r = subprocess.run(['openssl', 'x509', '-checkend', str(30 * 86400), '-noout', '-in', f'{CERTS}/server.pem'])
        neu = r.returncode != 0
    if neu:
        open(f'{CERTS}/server.ext', 'w').write('basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:radius.zenz.home\n')
        ossl('req', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-keyout', f'{CERTS}/server.key', '-out', f'{CERTS}/server.csr', '-subj', '/O=Netz Zenz/CN=radius.zenz.home')
        ossl('x509', '-req', '-in', f'{CERTS}/server.csr', '-CA', f'{CERTS}/ca.pem', '-CAkey', f'{CERTS}/ca.key', '-CAcreateserial', '-days', '825', '-sha256',
             '-extfile', f'{CERTS}/server.ext', '-out', f'{CERTS}/server.pem')
        log('Neues Server-Zertifikat radius.zenz.home erzeugt (825 Tage)')
    for f in ('ca.key', 'server.key'):
        lesbar(f'{CERTS}/{f}')
    try:
        os.makedirs(SHARE, exist_ok=True)
        open(f'{SHARE}/netz-zenz-radius-ca.crt', 'w').write(open(f'{CERTS}/ca.pem').read())
    except Exception:
        pass
    fp = subprocess.run(['openssl', 'x509', '-noout', '-fingerprint', '-sha256', '-enddate', '-in', f'{CERTS}/server.pem'], capture_output=True, text=True).stdout.split('\n')
    return [z for z in fp if z]

def ma_wert():
    ma = ma_modus()
    return ('yes' if MA_PFLICHT else ma), ma

def config_schreiben():
    ma, basis = ma_wert()
    lp = '  limit_proxy_state = auto\n' if basis == 'auto' else ''
    with open(f'{RADDB}/clients.conf', 'w') as f:
        for ip, name in SWITCHES.items():
            k = kurzname(name, ip)
            f.write(f'client {k} {{\n  ipaddr = {ip}\n  secret = "{SECRET}"\n  shortname = {k}\n  require_message_authenticator = {ma}\n{lp}  virtual_server = mab\n}}\n')
        for ip, name in APS.items():
            k = kurzname(name, ip)
            f.write(f'client {k} {{\n  ipaddr = {ip}\n  secret = "{WLAN_SECRET}"\n  shortname = {k}\n  require_message_authenticator = {ma}\n{lp}  virtual_server = wlan\n}}\n')
    # eigene schlanke virtuelle Server: mab (Switch-Ports) und wlan/wlan-inner (802.1X)
    for d in ('sites-enabled', 'mods-enabled'):
        for n in os.listdir(f'{RADDB}/{d}'):
            if (d == 'sites-enabled') or n in ('eap', 'inner-eap', 'wlanusers'):
                os.remove(f'{RADDB}/{d}/{n}')
    with open(f'{RADDB}/sites-enabled/mab', 'w') as f:
        f.write('''server mab {
  listen {
    type = auth
    ipaddr = *
    port = 1812
  }
  authorize {
    files
    chap
    pap
  }
  authenticate {
    Auth-Type CHAP {
      chap
    }
    Auth-Type PAP {
      pap
    }
  }
  post-auth {
    Post-Auth-Type REJECT {
    }
  }
}
''')
    if APS:
        open(f'{RADDB}/mods-enabled/wlanusers', 'w').write('files wlanusers {\n  filename = ${modconfdir}/files/wlan_users\n}\n')
        open(f'{RADDB}/mods-enabled/eap', 'w').write(f'''eap {{
  default_eap_type = peap
  timer_expire = 60
  ignore_unknown_eap_types = no
  max_sessions = ${{max_requests}}
  tls-config tls-common {{
    private_key_file = {CERTS}/server.key
    certificate_file = {CERTS}/server.pem
    ca_file = {CERTS}/ca.pem
    cipher_list = "DEFAULT"
    cipher_server_preference = no
    tls_min_version = "1.2"
    tls_max_version = "1.2"
    ecdh_curve = "prime256v1"
    cache {{
      enable = no
    }}
  }}
  peap {{
    tls = tls-common
    default_eap_type = mschapv2
    copy_request_to_tunnel = no
    use_tunneled_reply = no
    virtual_server = "wlan-inner"
  }}
  ttls {{
    tls = tls-common
    default_eap_type = md5
    copy_request_to_tunnel = no
    use_tunneled_reply = no
    virtual_server = "wlan-inner"
  }}
  mschapv2 {{
  }}
}}
''')
        open(f'{RADDB}/sites-enabled/wlan', 'w').write('''server wlan {
  authorize {
    eap {
      ok = return
      updated = return
    }
    reject
  }
  authenticate {
    eap
  }
  post-auth {
    Post-Auth-Type REJECT {
      eap
    }
  }
}
server wlan-inner {
  authorize {
    wlanusers
    mschap
    eap {
      ok = return
    }
    pap
  }
  authenticate {
    Auth-Type PAP {
      pap
    }
    Auth-Type MS-CHAP {
      mschap
    }
    eap
  }
  post-auth {
    Post-Auth-Type REJECT {
    }
  }
}
''')
        open(f'{RADDB}/mods-config/files/wlan_users', 'w').write('')
        lesbar(f'{RADDB}/mods-config/files/wlan_users')
    rc = f'{RADDB}/radiusd.conf'
    s = open(rc).read()
    s = re.sub(r'(\n\s*auth\s*=\s*)no', r'\1yes', s, count=1)
    open(rc, 'w').write(s)
    if not os.path.exists(f'{RADDB}/mods-config/files/authorize'):
        open(f'{RADDB}/mods-config/files/authorize', 'w').write('')

def inventar():
    d = http(f'{HA}/api/services/todo/get_items?return_response', {'entity_id': 'todo.netzwerk_gerate', 'status': ['needs_action', 'completed']}, auth=True)
    items = d['service_response']['todo.netzwerk_gerate']['items']
    erlaubt, namen = set(), {}
    for it in items:
        m = MAC_RE.search(it.get('summary', ''))
        if not m:
            continue
        mac = m.group(1).lower()
        namen[mac] = it['summary'].split(' · ')[0].replace('⏳ ', '').replace('⛔ ', '').strip()
        if it.get('status') == 'completed' and not it['summary'].startswith('⛔'):
            erlaubt.add(mac)
    return erlaubt, namen

STAMM_LISTE = OPT.get('benutzer_liste') or 'todo.netz_radius_benutzer'
STAMM = {}
WIRKSAM = {}

def stammdaten():
    try:
        d = http(f'{HA}/api/services/todo/get_items?return_response', {'entity_id': STAMM_LISTE, 'status': ['needs_action', 'completed']}, auth=True)
        items = d['service_response'][STAMM_LISTE]['items']
    except Exception:
        return None  # Liste nicht erreichbar → letzten Stand behalten
    st = {}
    for it in items:
        n = (it.get('summary') or '').strip().lower()
        if not NAME_RE.match(n):
            continue
        try:
            m = json.loads(it.get('description') or '{}')
        except Exception:
            m = {}
        m['_uid'] = it.get('uid')
        m['_status'] = it.get('status')
        st[n] = m
    return st

try:
    TEMP = json.load(open(TEMPF))
except Exception:
    TEMP = {}

def jetzt():
    return datetime.now()

def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M')

def benutzer_status(name):
    # ok | angefragt | gesperrt | abgelaufen | kennwort_abgelaufen | mail_fehlt | kennwort_fehlt
    m = STAMM.get(name)
    dauerhaft = name in {b['name'].lower() for b in BENUTZER}
    if m is not None:
        if m.get('_status') == 'needs_action':
            return 'angefragt'
        if m.get('aktiv') is False:
            return 'gesperrt'
        if m.get('gueltig_bis'):
            try:
                if datetime.strptime(m['gueltig_bis'][:10], '%Y-%m-%d').date() < jetzt().date():
                    return 'abgelaufen'
            except ValueError:
                pass
    if dauerhaft:
        return 'ok'
    if m is None:
        return 'kennwort_fehlt'
    t = TEMP.get(name)
    if not t:
        return 'mail_fehlt' if not m.get('mail') or not SMTP['smtp_server'] else 'kennwort_fehlt'
    if datetime.strptime(t['bis'], '%Y-%m-%dT%H:%M') < jetzt():
        return 'kennwort_abgelaufen'
    return 'ok'

def stamm_aendern(name, **felder):
    m = dict(STAMM.get(name) or {})
    uid = m.pop('_uid', None)
    m.pop('_status', None)
    m.update(felder)
    if uid:
        http(f'{HA}/api/services/todo/update_item', {'entity_id': STAMM_LISTE, 'item': uid, 'description': json.dumps(m, ensure_ascii=False)}, auth=True)
    STAMM.setdefault(name, {}).update(felder)

def kennwort_neu():
    import secrets
    zeichen = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    while True:
        pw = ''.join(secrets.choice(zeichen) for _ in range(14))
        if any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(c.islower() for c in pw):
            return pw

def mail_senden(an, betreff, text):
    import smtplib, ssl
    from email.message import EmailMessage
    msg = EmailMessage()
    msg['From'] = SMTP['smtp_absender'] or SMTP['smtp_benutzer']
    msg['To'] = an
    msg['Subject'] = betreff
    msg.set_content(text)
    ctx = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP['smtp_server'], SMTP_PORT, context=ctx, timeout=20) as m:
            if SMTP['smtp_benutzer']:
                m.login(SMTP['smtp_benutzer'], SMTP['smtp_passwort'])
            m.send_message(msg)
    else:
        with smtplib.SMTP(SMTP['smtp_server'], SMTP_PORT, timeout=20) as m:
            if SMTP_PORT != 25 or os.environ.get('SMTP_STARTTLS') == '1':
                m.starttls(context=ctx)
            if SMTP['smtp_benutzer']:
                m.login(SMTP['smtp_benutzer'], SMTP['smtp_passwort'])
            m.send_message(msg)

def audit(titel, objekt, details, kategorie='Zugangskontrolle'):
    try:
        if AUDIT_URL:
            http(AUDIT_URL, {'kategorie': kategorie, 'titel': titel, 'objekt': objekt, 'details': details, 'wer': 'Netz-RADIUS', 'quelle': 'Netz-RADIUS'})
    except Exception as x:
        log('Audit:', repr(x))

def gaeste_bearbeiten():
    """Freigegebene Benutzer ohne festes Kennwort: Kennwort erzeugen, per Mail senden, nach Ablauf sperren."""
    dauerhaft = {b['name'].lower() for b in BENUTZER}
    geaendert = False
    for name in list(TEMP):
        if name not in STAMM:
            TEMP.pop(name)
            geaendert = True
    for name, m in STAMM.items():
        if name in dauerhaft or m.get('_status') != 'completed' or m.get('aktiv') is False:
            continue
        if benutzer_status(name) == 'abgelaufen':
            continue
        if name in TEMP and not m.get('neu_senden'):
            continue
        if not m.get('mail') or not SMTP['smtp_server']:
            continue
        pw = kennwort_neu()
        bis = jetzt() + timedelta(hours=GAST_STUNDEN)
        anrede = m.get('vorname') or name
        text = (f'Hallo {anrede},\n\nDein WLAN-Zugang wurde freigegeben.\n\n'
                f'  WLAN:          {PROFIL_SSID}\n  Benutzername:  {name}\n  Kennwort:      {pw}\n  Gültig bis:    {bis.strftime("%d.%m.%Y %H:%M")} Uhr\n\n'
                f'Beim ersten Verbinden fragt dein Gerät nach dem Zertifikat „{SERVERNAME}“ (ausgestellt von „Netz Zenz RADIUS CA“) – bitte bestätigen.\n'
                + (f'Einrichtungshilfe im Netz: {PROFIL_URL}\n' if PROFIL_URL else '') +
                '\nDas Kennwort ist persönlich – bitte nicht weitergeben.\n\nNetz Zenz')
        try:
            mail_senden(m['mail'], f'WLAN-Zugang {PROFIL_SSID}', text)
        except Exception as x:
            log('Mail an', m['mail'], 'fehlgeschlagen:', repr(x))
            if not m.get('mail_fehler'):
                stamm_aendern(name, mail_fehler=str(x)[:120])
                audit('RADIUS: Kennwort-Mail fehlgeschlagen', name, f'{m["mail"]}: {x}', 'Vorfall')
            continue
        TEMP[name] = {'pw': pw, 'bis': iso(bis)}
        geaendert = True
        stamm_aendern(name, pw_bis=iso(bis), pw_gesendet=iso(jetzt()), neu_senden=False, mail_fehler='')
        audit('RADIUS: WLAN-Kennwort per Mail gesendet', name, f'an {m["mail"]}, gültig bis {bis.strftime("%d.%m.%Y %H:%M")}')
        log('Gast-Kennwort gesendet:', name, 'gültig bis', iso(bis))
    if geaendert:
        json.dump(TEMP, open(TEMPF, 'w'))
        os.chmod(TEMPF, 0o600)

def wlan_benutzer_schreiben():
    global STAMM, WIRKSAM
    st = stammdaten()
    if st is not None:
        STAMM = st
        try:
            gaeste_bearbeiten()
        except Exception as x:
            log('Gäste:', repr(x))
    pw = {b['name'].lower(): b['passwort'] for b in BENUTZER}
    pw.update({n: t['pw'] for n, t in TEMP.items() if n not in pw})
    WIRKSAM = {n: p for n, p in pw.items() if benutzer_status(n) == 'ok'}
    zeilen = ['# automatisch: Kennwort aus App-Konfiguration bzw. Gast-Kennwort, Status aus todo.netz_radius_benutzer – nicht von Hand ändern']
    for n, p in sorted(WIRKSAM.items()):
        p = p.replace('\\', '\\\\').replace('"', '\\"')
        zeilen.append(f'{n}\tCleartext-Password := "{p}"')
    neu = '\n'.join(zeilen) + '\n'
    pf = f'{RADDB}/mods-config/files/wlan_users'
    alt = open(pf).read() if os.path.exists(pf) else None
    if alt != neu:
        open(pf, 'w').write(neu)
        lesbar(pf)
        return alt is not None
    return False

NAMEN = {}
ZERT = []
def sync():
    global NAMEN
    wlan_neu = wlan_benutzer_schreiben() if APS else False
    erlaubt, NAMEN = inventar()
    zeilen = ['# automatisch aus todo.netzwerk_gerate – nicht von Hand ändern']
    for mac in sorted(erlaubt):
        for v in varianten(mac):
            zeilen.append(f'{v}\tCleartext-Password := "{v}"\n\tReply-Message = "{NAMEN.get(mac, "")[:60]}"')
    neu = '\n'.join(zeilen) + '\n'
    pf = f'{RADDB}/mods-config/files/authorize'
    if open(pf).read() != neu:
        open(pf, 'w').write(neu)
        return len(erlaubt), True
    return len(erlaubt), wlan_neu

# ------------------------------------------------------------------ Auswertung der Anmeldungen
ZEILE = re.compile(r'Login (OK|incorrect)[^\[]*\[([^\]/]*)[^\]]*\].*?\(from client (\S+) port (\d+)(?: cli ([0-9A-Fa-f:.-]+))?')

AP_KURZ = {}
def ereignis(ok, user, client, port, cli, tunnel=False):
    if client in AP_KURZ:
        return wlan_ereignis(ok, user, client, cli, tunnel)
    mac = mac_norm(cli or user)
    if not mac:
        return
    name = NAMEN.get(mac, '')
    e = {'zeit': datetime.now().strftime('%d.%m. %H:%M'), 'ok': ok, 'mac': mac, 'name': name or 'unbekannt', 'switch': client, 'port': port}
    with LOCK:
        LETZTE.appendleft(e)
        if ok:
            ST['ok'][mac] = int(time.time())
        else:
            letzte = ST['gemeldet'].get(mac, 0)
            if time.time() - letzte > 86400:
                ST['gemeldet'][mac] = int(time.time())
                threading.Thread(target=melden, args=(mac, name, client, port), daemon=True).start()
    log('RADIUS', 'OK' if ok else 'ABGELEHNT', mac, name, client, 'Port', port)

INNEN = {}
def wlan_ereignis(ok, user, ap, cli, tunnel):
    # innere Zeile (via TLS tunnel) trägt den echten Benutzernamen, die äußere die MAC des Geräts
    if tunnel:
        INNEN[ap] = ((user or '').strip(), time.time())
        return
    innen = INNEN.pop(ap, None)
    if innen and time.time() - innen[1] < 10 and innen[0]:
        user = innen[0]
    mac = mac_norm(cli or '')
    user = (user or '').strip() or 'unbekannt'
    e = {'zeit': datetime.now().strftime('%d.%m. %H:%M'), 'ok': ok, 'mac': mac, 'name': user, 'switch': AP_KURZ.get(ap, ap), 'port': 'WLAN', 'wlan': True}
    with LOCK:
        LETZTE.appendleft(e)
        if ok:
            w = ST.setdefault('wlan', {}).setdefault(user, {'macs': []})
            w['zeit'] = e['zeit']
            w['ap'] = e['switch']
            if mac:
                w['macs'] = ([mac] + [x for x in w.get('macs', []) if x != mac])[:5]
        schluessel = f'wlan:{user}:{mac}'
        if not ok and time.time() - ST['gemeldet'].get(schluessel, 0) > 3600:
            ST['gemeldet'][schluessel] = int(time.time())
            threading.Thread(target=wlan_melden, args=(user, mac, AP_KURZ.get(ap, ap)), daemon=True).start()
    log('WLAN', 'OK' if ok else 'ABGELEHNT', user, mac, AP_KURZ.get(ap, ap))

def wlan_melden(user, mac, ap):
    try:
        if AUDIT_URL:
            http(AUDIT_URL, {'kategorie': 'Vorfall', 'titel': 'WLAN-802.1X: Anmeldung abgelehnt', 'objekt': user, 'details': f'Gerät {mac or "?"} an {ap} – falsches Kennwort, unbekannter Benutzer oder Zertifikat nicht akzeptiert', 'wer': 'Netz-RADIUS', 'quelle': 'Netz-RADIUS'})
    except Exception as x:
        log('Meldung fehlgeschlagen:', repr(x))

def melden(mac, name, client, port):
    text = f'{client} Port {port}' + (f' – im Inventar als „{name}“, aber nicht freigegeben' if name else '')
    try:
        if AUDIT_URL:
            http(AUDIT_URL, {'kategorie': 'Vorfall', 'titel': 'RADIUS: Gerät am Switch-Port abgelehnt', 'objekt': mac, 'details': text, 'wer': 'Netz-RADIUS', 'quelle': 'Netz-RADIUS'})
        if NAC_WEBHOOK:
            http(NAC_WEBHOOK, {'event': 'radius', 'mac': mac, 'ip': '', 'hostname': '', 'vorher': '', 'port': f'{client} Port {port}'})
    except Exception as x:
        log('Meldung fehlgeschlagen:', repr(x))

def benutzer_liste():
    namen = sorted({b['name'].lower() for b in BENUTZER} | set(STAMM))
    w = ST.get('wlan', {})
    dauerhaft = {b['name'].lower() for b in BENUTZER}
    return [{'name': n, 'status': benutzer_status(n), 'stammdaten': n in STAMM, 'art': 'dauerhaft' if n in dauerhaft else 'gast',
             'kennwort_bis': '' if n in dauerhaft else TEMP.get(n, {}).get('bis', ''), 'letzte': w.get(n, {}).get('zeit', ''),
             'ap': w.get(n, {}).get('ap', ''), 'geraete': w.get(n, {}).get('macs', [])} for n in namen]

def sensor(anzahl):
    if not TOKEN:
        return
    with LOCK:
        l = list(LETZTE)
        abgelehnt = sorted({e['mac'] for e in l if not e['ok'] and not e.get('wlan')})
    try:
        http(f'{HA}/api/states/sensor.netz_radius', {'state': anzahl, 'attributes': {
            'friendly_name': 'RADIUS freigegebene Geräte', 'icon': 'mdi:shield-key-outline', 'unit_of_measurement': 'Geräte',
            'letzte': l[:20], 'abgelehnt_zuletzt': abgelehnt, 'switches': list(SWITCHES.values()),
            'wlan_aps': list(APS.values()), 'wlan_benutzer': benutzer_liste(), 'zertifikat': ZERT, 'profilseite_port': PROFIL_PORT, 'mail_bereit': bool(SMTP['smtp_server'])}}, auth=True)
    except Exception as x:
        log('Sensor:', repr(x))

def leser(proc):
    for z in proc.stdout:
        z = z.rstrip()
        m = ZEILE.search(z)
        if m:
            ereignis(m.group(1) == 'OK', m.group(2), m.group(3), m.group(4), m.group(5), 'via TLS tunnel' in z)
        elif 'rror' in z or 'arning' in z:
            log(z)


# ------------------------------------------------------------------ Geräteprofile (nur öffentliche Daten: CA, SSID, Servername)
import base64, plistlib, uuid, html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

def ca_der():
    pem = open(f'{CERTS}/ca.pem').read()
    b64 = ''.join(z for z in pem.splitlines() if z and not z.startswith('-----'))
    return base64.b64decode(b64)

def ca_fingerprint(alg='sha256'):
    r = subprocess.run(['openssl', 'x509', '-noout', '-fingerprint', f'-{alg}', '-in', f'{CERTS}/ca.pem'], capture_output=True, text=True).stdout.strip()
    return r.split('=', 1)[-1]

def mobileconfig(user, ssid):
    ns = uuid.UUID('6f1c2b8e-5d4a-4c1e-9a3b-7e2f0d9c4b11')
    ca_uuid = str(uuid.uuid5(ns, 'ca' + ca_fingerprint())).upper()
    wifi_uuid = str(uuid.uuid5(ns, 'wifi' + ssid + user)).upper()
    eap = {'AcceptEAPTypes': [25, 21], 'TLSTrustedServerNames': [SERVERNAME], 'TTLSInnerAuthentication': 'PAP',
           'PayloadCertificateAnchorUUID': [ca_uuid], 'TLSAllowTrustExceptions': False}
    if user:
        eap['UserName'] = user
    inhalt = [
        {'PayloadType': 'com.apple.security.root', 'PayloadVersion': 1, 'PayloadIdentifier': f'home.zenz.radius.ca.{ca_uuid}',
         'PayloadUUID': ca_uuid, 'PayloadDisplayName': 'Netz Zenz RADIUS CA', 'PayloadCertificateFileName': 'netz-zenz-radius-ca.cer',
         'PayloadContent': ca_der()},
        {'PayloadType': 'com.apple.wifi.managed', 'PayloadVersion': 1, 'PayloadIdentifier': f'home.zenz.wifi.{wifi_uuid}',
         'PayloadUUID': wifi_uuid, 'PayloadDisplayName': f'WLAN {ssid}', 'SSID_STR': ssid, 'HIDDEN_NETWORK': False,
         'AutoJoin': True, 'EncryptionType': 'WPA2', 'IsHotspot': False, 'ProxyType': 'None',
         'EAPClientConfiguration': eap, 'PayloadCertificateUUID': None},
    ]
    del inhalt[1]['PayloadCertificateUUID']
    profil = {'PayloadType': 'Configuration', 'PayloadVersion': 1, 'PayloadIdentifier': f'home.zenz.netz.{ssid.lower()}.{user or "alle"}',
              'PayloadUUID': str(uuid.uuid5(ns, 'profil' + ssid + user)).upper(), 'PayloadDisplayName': f'Netz Zenz – WLAN {ssid}',
              'PayloadDescription': f'Vertraut der Netz-Zenz-CA nur für {SERVERNAME} und richtet das WLAN {ssid} (WPA2-Enterprise) ein. Enthält kein Kennwort.',
              'PayloadOrganization': 'Netz Zenz', 'PayloadRemovalDisallowed': False, 'PayloadContent': inhalt}
    return plistlib.dumps(profil)

def windows_xml(ssid):
    fp = ca_fingerprint('sha1').replace(':', ' ').lower()  # Windows erwartet den SHA-1-Thumbprint
    hexssid = ssid.encode().hex().upper()
    return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{html.escape(ssid)}</name>
  <SSIDConfig><SSID><hex>{hexssid}</hex><name>{html.escape(ssid)}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType><connectionMode>auto</connectionMode>
  <MSM><security>
    <authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>
    <OneX xmlns="http://www.microsoft.com/networking/OneX/v1"><authMode>user</authMode>
      <EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
        <EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod>
        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>25</Type>
          <EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">
            <ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>{SERVERNAME}</ServerNames><TrustedRootCA>{fp}</TrustedRootCA></ServerValidation>
            <FastReconnect>true</FastReconnect><InnerEapOptional>false</InnerEapOptional>
            <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap>
            <EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>false</RequireCryptoBinding>
            <PeapExtensions><PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation><AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</AcceptServerName></PeapExtensions>
          </EapType></Eap></Config>
      </EapHostConfig></EAPConfig>
    </OneX>
  </security></MSM>
</WLANProfile>
"""

SEITE = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netz Zenz – WLAN einrichten</title><style>body{{font-family:-apple-system,Segoe UI,sans-serif;max-width:640px;margin:24px auto;padding:0 16px;color:#1a1a1a}}
h1{{font-size:22px}}a.b{{display:block;padding:14px 16px;margin:10px 0;background:#0b5cad;color:#fff;text-decoration:none;font-size:17px}}
code{{background:#f1f3f5;padding:2px 5px;word-break:break-all}}li{{margin:6px 0}}.k{{color:#555;font-size:14px}}</style></head><body>
<h1>WLAN „{ssid}“ einrichten</h1>
<p><a href="/anfrage">Noch keinen Zugang? Hier anfragen →</a></p>
<p class="k">Server-Zertifikat: <b>{server}</b> · CA „Netz Zenz RADIUS CA“<br>CA-Fingerabdruck (SHA-256): <code>{fp}</code></p>
<h2>iPhone / iPad</h2>
{nutzer}
<ol><li>Vorher unter Einstellungen → WLAN bei „{ssid}“ auf ⓘ → <i>Dieses Netzwerk ignorieren</i>.</li>
<li>Profil hier in <b>Safari</b> laden → <i>Zulassen</i>.</li><li>Einstellungen → <i>Profil geladen</i> → Installieren (Code des iPhones).</li>
<li>Beim Verbinden nur noch das WLAN-Kennwort eingeben – keine Zertifikatsfrage mehr.</li></ol>
<h2>Windows</h2>
<a class="b" href="/netz-zenz-radius-ca.cer">CA-Zertifikat (.cer)</a>
<a class="b" href="/{ssid}.xml">WLAN-Profil (.xml)</a>
<ol><li>CA-Datei öffnen → Zertifikat installieren → Lokaler Computer → <i>Vertrauenswürdige Stammzertifizierungsstellen</i>.</li>
<li>Eingabeaufforderung: <code>netsh wlan add profile filename="%USERPROFILE%\\Downloads\\{ssid}.xml"</code></li>
<li>Mit „{ssid}“ verbinden, Benutzer + Kennwort eingeben.</li></ol>
</body></html>"""


ANFRAGE_SEITE = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netz Zenz – WLAN-Zugang anfragen</title><style>body{{font-family:-apple-system,Segoe UI,sans-serif;max-width:560px;margin:24px auto;padding:0 16px;color:#1a1a1a}}
h1{{font-size:22px}}label{{display:block;margin:12px 0 4px;font-size:14px;color:#444}}input,textarea{{width:100%;box-sizing:border-box;padding:10px;font-size:16px;border:1px solid #bbb;border-radius:0}}
textarea{{min-height:80px}}button{{margin-top:16px;width:100%;padding:14px;font-size:17px;background:#0b5cad;color:#fff;border:0}}.f{{color:#b00020}}.k{{color:#555;font-size:14px}}.hp{{position:absolute;left:-5000px}}</style></head><body>
<h1>WLAN-Zugang anfragen</h1><p class="k">Deine Anfrage wird von Stefan oder Kristina geprüft. Nach der Freigabe bekommst du Benutzername und ein Kennwort per Mail – gültig {stunden} Stunden.</p>
{fehler}<form method="post" action="/anfrage">
<label>Vorname *</label><input name="vorname" required maxlength="40" value="{vorname}">
<label>Nachname *</label><input name="nachname" required maxlength="40" value="{nachname}">
<label>E-Mail *</label><input name="mail" type="email" required maxlength="80" value="{mail}">
<label>Telefon</label><input name="telefon" type="tel" maxlength="30" value="{telefon}">
<label>Firma</label><input name="firma" maxlength="60" value="{firma}">
<label>Grund des Besuchs *</label><textarea name="grund" required maxlength="300">{grund}</textarea>
<div class="hp"><label>Website</label><input name="website" tabindex="-1" autocomplete="off"></div>
<button type="submit">Anfrage senden</button></form>
<p class="k">Deine Angaben werden nur für die Verwaltung des WLAN-Zugangs gespeichert.</p></body></html>"""

DANKE_SEITE = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Danke</title>
<style>body{font-family:-apple-system,Segoe UI,sans-serif;max-width:560px;margin:24px auto;padding:0 16px}</style></head><body>
<h1>Danke!</h1><p>Deine Anfrage ist eingegangen. Sobald sie freigegeben ist, bekommst du eine Mail mit deinen Zugangsdaten.</p></body></html>"""

ANFRAGEN_IP = {}
UMLAUT = str.maketrans({'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'ß': 'ss', 'é': 'e', 'è': 'e', 'á': 'a', 'à': 'a', 'ó': 'o', 'ú': 'u', 'í': 'i', 'č': 'c', 'š': 's', 'ž': 'z', 'ć': 'c'})

def benutzername(vorname, nachname):
    basis = re.sub(r'[^a-z0-9]', '', vorname.lower().translate(UMLAUT))[:15] + '.' + re.sub(r'[^a-z0-9]', '', nachname.lower().translate(UMLAUT))[:15]
    basis = basis.strip('.') or 'gast'
    vergeben = set(STAMM) | {b['name'].lower() for b in BENUTZER}
    n, i = basis, 2
    while n in vergeben:
        n, i = f'{basis}{i}', i + 1
    return n

def anfrage_anlegen(f, ip):
    jetzt_ts = time.time()
    liste = [t for t in ANFRAGEN_IP.get(ip, []) if jetzt_ts - t < 3600]
    if len(liste) >= 3:
        return 'Zu viele Anfragen von diesem Gerät – bitte später erneut versuchen.'
    if sum(1 for m in STAMM.values() if m.get('_status') == 'needs_action') >= 10:
        return 'Es sind gerade zu viele Anfragen offen – bitte später erneut versuchen.'
    if not f['vorname'] or not f['nachname'] or not f['grund'] or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', f['mail']):
        return 'Bitte Vorname, Nachname, eine gültige E-Mail und den Grund angeben.'
    name = benutzername(f['vorname'], f['nachname'])
    daten = {k: f[k] for k in ('vorname', 'nachname', 'mail', 'telefon', 'firma', 'grund')}
    daten.update({'aktiv': True, 'art': 'gast', 'quelle': 'formular', 'angefragt': iso(jetzt())})
    http(f'{HA}/api/services/todo/add_item', {'entity_id': STAMM_LISTE, 'item': name, 'description': json.dumps(daten, ensure_ascii=False)}, auth=True)
    STAMM[name] = {**daten, '_status': 'needs_action'}
    liste.append(jetzt_ts)
    ANFRAGEN_IP[ip] = liste
    try:
        http(f'{HA}/api/events/netz_radius_anfrage', {'name': name, 'vorname': f['vorname'], 'nachname': f['nachname'], 'firma': f['firma'], 'grund': f['grund'][:120], 'mail': f['mail']}, auth=True)
    except Exception as x:
        log('Ereignis Anfrage:', repr(x))
    audit('RADIUS: WLAN-Zugang angefragt', name, f'{f["vorname"]} {f["nachname"]}{" (" + f["firma"] + ")" if f["firma"] else ""} – {f["grund"][:120]} – von {ip}')
    log('Zugangsanfrage:', name, 'von', ip)
    return None

class Profile(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def senden(self, daten, typ, name=None):
        self.send_response(200)
        self.send_header('Content-Type', typ)
        if name:
            self.send_header('Content-Disposition', f'attachment; filename="{name}"')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(daten)
    def do_POST(self):
        if urlparse(self.path).path != '/anfrage':
            self.send_response(404)
            self.end_headers()
            return
        try:
            n = min(int(self.headers.get('Content-Length') or 0), 8000)
            q = parse_qs(self.rfile.read(n).decode('utf-8', 'replace'))
            f = {k: (q.get(k) or [''])[0].strip()[:300] for k in ('vorname', 'nachname', 'mail', 'telefon', 'firma', 'grund', 'website')}
            if f['website']:
                return self.senden(DANKE_SEITE.encode(), 'text/html; charset=utf-8')  # Spam-Falle
            fehler = anfrage_anlegen(f, self.client_address[0])
            if fehler:
                esc = {k: html.escape(v) for k, v in f.items() if k != 'website'}
                return self.senden(ANFRAGE_SEITE.format(stunden=GAST_STUNDEN, fehler=f'<p class="f">{html.escape(fehler)}</p>', **esc).encode(), 'text/html; charset=utf-8')
            return self.senden(DANKE_SEITE.encode(), 'text/html; charset=utf-8')
        except Exception as x:
            log('Anfrage:', repr(x))
            self.send_response(500)
            self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path in ('/', '/index.html'):
                knoepfe = ''.join(f'<a class="b" href="/profil.mobileconfig?u={html.escape(b["name"].lower())}">Profil für {html.escape(b["name"].lower())}</a>' for b in BENUTZER)
                knoepfe += '<a class="b" href="/profil.mobileconfig">Profil ohne Benutzernamen</a>'
                return self.senden(SEITE.format(ssid=html.escape(PROFIL_SSID), server=SERVERNAME, fp=ca_fingerprint(), nutzer=knoepfe).encode(), 'text/html; charset=utf-8')
            if u.path == '/profil.mobileconfig':
                user = (q.get('u') or [''])[0].lower()
                if user and user not in [b['name'].lower() for b in BENUTZER]:
                    user = ''
                return self.senden(mobileconfig(user, PROFIL_SSID), 'application/x-apple-aspen-config', f'Netz-Zenz-{PROFIL_SSID}.mobileconfig')
            if u.path in ('/netz-zenz-radius-ca.cer', '/ca.cer'):
                return self.senden(ca_der(), 'application/pkix-cert', 'netz-zenz-radius-ca.cer')
            if u.path == '/anfrage':
                leer = {k: '' for k in ('vorname', 'nachname', 'mail', 'telefon', 'firma', 'grund')}
                return self.senden(ANFRAGE_SEITE.format(stunden=GAST_STUNDEN, fehler='', **leer).encode(), 'text/html; charset=utf-8')
            if u.path == f'/{PROFIL_SSID}.xml':
                return self.senden(windows_xml(PROFIL_SSID).encode(), 'application/xml', f'{PROFIL_SSID}.xml')
        except Exception as x:
            log('Profilseite:', repr(x))
        self.send_response(404)
        self.end_headers()

def profil_server():
    try:
        ThreadingHTTPServer(('0.0.0.0', PROFIL_PORT), Profile).serve_forever()
    except Exception as x:
        log('Profilseite nicht gestartet:', repr(x))

def main():
    if not SECRET:
        log('Kein radius_secret gesetzt – bitte in der App-Konfiguration eintragen. Server startet nicht.')
        while True:
            time.sleep(3600)
    global ZERT
    for ip, name in APS.items():
        AP_KURZ[kurzname(name, ip)] = name
    if APS:
        ZERT = zertifikate()
        for z in ZERT:
            log('Zertifikat:', z)
    config_schreiben()
    anzahl, _ = sync()
    log(f'Inventar: {anzahl} freigegebene Geräte; Switches: {", ".join(f"{n} ({i})" for i, n in SWITCHES.items())}')
    if APS and PROFIL_PORT:
        threading.Thread(target=profil_server, daemon=True).start()
        log(f'Geräteprofile: http://<HA-IP>:{PROFIL_PORT}/ (WLAN {PROFIL_SSID})')
    if APS:
        log(f'WLAN-802.1X: {len(APS)} Access Points, aktive Benutzer: {", ".join(sorted(WIRKSAM)) or "keine"}' + (f' (nicht aktiv: {", ".join(f"{b['name']}={b['status']}" for b in benutzer_liste() if b['status'] != 'ok')})' if any(b['status'] != 'ok' for b in benutzer_liste()) else ''))
    sensor(anzahl)
    proc = subprocess.Popen([RADIUSD, *RADIUSD_ARGS, '-f', '-l', 'stdout'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    threading.Thread(target=leser, args=(proc,), daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *a: (proc.terminate(), os._exit(0)))
    while proc.poll() is None:
        time.sleep(SYNC)
        try:
            anzahl, geaendert = sync()
            if geaendert:
                proc.send_signal(signal.SIGHUP)
                log('Inventar/Benutzer geändert – RADIUS neu geladen,', anzahl, 'freigegebene Geräte, WLAN-Benutzer aktiv:', ', '.join(sorted(WIRKSAM)) or 'keine')
            sensor(anzahl)
            json.dump(ST, open(STATEF, 'w'))
        except Exception as x:
            log('Sync:', repr(x))
    log('radiusd beendet mit Code', proc.returncode)
    raise SystemExit(1)

if __name__ == '__main__':
    main()
