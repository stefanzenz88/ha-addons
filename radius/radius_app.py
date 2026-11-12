#!/usr/bin/env python3
"""Netz-RADIUS: FreeRADIUS für MAC-Authentifizierung (MAB) der Switch-Ports.
Freigegebene MACs kommen aus dem Home-Assistant-Geräteinventar (todo.netzwerk_gerate, abgehakt und nicht ⛔).
Ergebnis jeder Anmeldung → Sensor sensor.netz_radius, Ablehnungen → Audit-Log + NAC-Freigabe-Push."""
import json, os, re, signal, subprocess, threading, time, urllib.request
from collections import deque
from datetime import datetime

OPT = json.load(open('/data/options.json')) if os.path.exists('/data/options.json') else {}
RADDB = os.environ.get('RADDB', '/etc/raddb')
RADIUSD = os.environ.get('RADIUSD', 'radiusd')
RADIUSD_ARGS = os.environ.get('RADIUSD_ARGS', '').split()
TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')
HA = os.environ.get('HA_URL', 'http://supervisor/core')
SECRET = OPT.get('radius_secret') or ''
SWITCHES = dict(s.split('=', 1) if '=' in s else (s, s) for s in OPT.get('switches', []))
SYNC = int(OPT.get('sync_sekunden', 60))
NAC_WEBHOOK = OPT.get('nac_webhook_url') or ''
AUDIT_URL = OPT.get('audit_url') or ''
MAC_RE = re.compile(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', re.I)
STATEF = '/data/radius_state.json'
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

def config_schreiben():
    ma = ma_modus()
    with open(f'{RADDB}/clients.conf', 'w') as f:
        for ip, name in SWITCHES.items():
            kurz = re.sub(r'[^A-Za-z0-9_-]', '', name) or ip.replace('.', '_')
            f.write(f'client {kurz} {{\n  ipaddr = {ip}\n  secret = "{SECRET}"\n  shortname = {kurz}\n  require_message_authenticator = {ma}\n' + ('  limit_proxy_state = auto\n' if ma == 'auto' else '') + '}\n')
    # schlanker eigener virtueller Server: nur MAB über files + CHAP/PAP
    for d in ('sites-enabled', 'mods-enabled'):
        for n in os.listdir(f'{RADDB}/{d}'):
            if (d == 'sites-enabled') or n in ('eap', 'inner-eap'):
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

def ereignis(ok, user, client, port, cli):
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
        abgelehnt = sorted({e['mac'] for e in l if not e['ok']})
    try:
        http(f'{HA}/api/states/sensor.netz_radius', {'state': anzahl, 'attributes': {
            'friendly_name': 'RADIUS freigegebene Geräte', 'icon': 'mdi:shield-key-outline', 'unit_of_measurement': 'Geräte',
            'letzte': l[:20], 'abgelehnt_zuletzt': abgelehnt, 'switches': list(SWITCHES.values())}}, auth=True)
    except Exception as x:
        log('Sensor:', repr(x))

def leser(proc):
    for z in proc.stdout:
        z = z.rstrip()
        m = ZEILE.search(z)
        if m:
            ereignis(m.group(1) == 'OK', m.group(2), m.group(3), m.group(4), m.group(5))
        elif 'rror' in z or 'arning' in z:
            log(z)

def main():
    if not SECRET:
        log('Kein radius_secret gesetzt – bitte in der App-Konfiguration eintragen. Server startet nicht.')
        while True:
            time.sleep(3600)
    config_schreiben()
    anzahl, _ = sync()
    log(f'Inventar: {anzahl} freigegebene Geräte; Switches: {", ".join(f"{n} ({i})" for i, n in SWITCHES.items())}')
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
