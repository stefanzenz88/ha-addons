#!/usr/bin/env python3
"""Netz-RADIUS: FreeRADIUS für MAC-Authentifizierung (MAB) der Switch-Ports und WLAN-802.1X (WPA-Enterprise).
Freigegebene MACs kommen aus dem Home-Assistant-Geräteinventar (todo.netzwerk_gerate, abgehakt und nicht ⛔).
WLAN-Benutzer kommen aus der App-Konfiguration (PEAP-MSCHAPv2 / TTLS-PAP, eigenes Zertifikat).
Ergebnis jeder Anmeldung → Sensor sensor.netz_radius, Ablehnungen → Audit-Log (+ NAC-Freigabe-Push bei Switch-Ports)."""
import json, os, re, signal, subprocess, threading, time, urllib.request
from collections import deque
from datetime import datetime

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
        zeilen = ['# automatisch aus der App-Konfiguration (wlan_benutzer) – nicht von Hand ändern']
        for b in BENUTZER:
            pw = b['passwort'].replace('\\', '\\\\').replace('"', '\\"')
            zeilen.append(f'{b["name"].lower()}\tCleartext-Password := "{pw}"')
        open(f'{RADDB}/mods-config/files/wlan_users', 'w').write('\n'.join(zeilen) + '\n')
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

NAMEN = {}
ZERT = []
def sync():
    global NAMEN
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
    return len(erlaubt), False

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
            'wlan_aps': list(APS.values()), 'wlan_benutzer': [b['name'].lower() for b in BENUTZER], 'zertifikat': ZERT}}, auth=True)
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
    if APS:
        log(f'WLAN-802.1X: {len(APS)} Access Points, {len(BENUTZER)} Benutzer ({", ".join(b["name"].lower() for b in BENUTZER) or "noch keine"})')
    proc = subprocess.Popen([RADIUSD, *RADIUSD_ARGS, '-f', '-l', 'stdout'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    threading.Thread(target=leser, args=(proc,), daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *a: (proc.terminate(), os._exit(0)))
    while proc.poll() is None:
        time.sleep(SYNC)
        try:
            anzahl, geaendert = sync()
            if geaendert:
                proc.send_signal(signal.SIGHUP)
                log('Inventar geändert – RADIUS neu geladen,', anzahl, 'freigegebene Geräte')
            sensor(anzahl)
            json.dump(ST, open(STATEF, 'w'))
        except Exception as x:
            log('Sync:', repr(x))
    log('radiusd beendet mit Code', proc.returncode)
    raise SystemExit(1)

if __name__ == '__main__':
    main()
