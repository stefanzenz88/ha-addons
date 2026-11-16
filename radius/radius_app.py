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
PROFIL_PORT = int(OPT.get('profil_port', 8098))
PROFIL_SSID = OPT.get('profil_ssid') or 'Zenz-Test'
SERVERNAME = 'radius.zenz.home'
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
