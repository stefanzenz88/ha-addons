#!/usr/bin/env python3
"""Netz-Logsammler: empfängt FortiGate-Syslog (UDP/TCP), archiviert die Rohzeilen
tageweise komprimiert, wertet den Internet-Verkehr je Gerät aus und meldet
Stand + Alarme per Webhook an Home Assistant. Suchseite über HA-Ingress."""
import asyncio, gzip, html, json, os, re, threading, time, urllib.parse, urllib.request
from collections import deque
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from audit import Audit

OPT = json.load(open('/data/options.json')) if os.path.exists('/data/options.json') else {}
PORT = int(OPT.get('port', 5514))
WEBHOOK = OPT.get('webhook_url') or ''
TAGE = int(OPT.get('aufbewahrung_tage', 21))
ABSENDER = set(OPT.get('erlaubte_absender') or [])
STAND_INTERVALL = int(OPT.get('stand_intervall_sekunden', 300))
UI_PORT = int(OPT.get('ui_port', 8097))
LOGDIR, STATEF = '/data/logs', '/data/state.json'
AUDIT = Audit('/data/audit.jsonl')
TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')
PERSONEN = {}
KATEGORIEN = ['Maßnahme', 'Konfiguration', 'Freigabe', 'Sperre', 'Vorfall', 'Prüfung', 'Sonstiges']
os.makedirs(LOGDIR, exist_ok=True)

PORTS = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'Mailversand (SMTP)', 139: 'NetBIOS',
         445: 'Windows-Dateifreigabe (SMB)', 1433: 'MS-SQL', 3389: 'Remote Desktop (RDP)',
         5900: 'VNC', 6667: 'IRC (Chat/Botnetz)', 9001: 'Tor', 9030: 'Tor', 9050: 'Tor'}
KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
SAUBER = re.compile(r'[^A-Za-z0-9 ._()-]')

def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, flush=True)

def heute():
    return datetime.now().strftime('%Y-%m-%d')

def leer():
    return {'tag': heute(), 'seit': heute(), 'g': {}, 'h': {}, 'lk': {}, 'gem': [], 'zeilen': 0,
            'verkehr': 0, 'letzte': 0, 'quelle': 'syslog'}

def laden():
    try:
        s = json.load(open(STATEF))
        if isinstance(s, dict) and 'g' in s:
            for k, v in leer().items():
                s.setdefault(k, v)
            return s
    except Exception:
        pass
    return leer()

S = laden()
LOCK = threading.Lock()
STAT = {'start': time.time(), 'empfangen': 0, 'verworfen': 0, 'absender': {}}

def speichern():
    with LOCK:
        tmp = STATEF + '.tmp'
        json.dump(S, open(tmp, 'w'))
        os.replace(tmp, STATEF)

def tageswechsel():
    """Gestrige Werte in den 7-Tage-Verlauf, Länder als bekannt übernehmen."""
    global S
    t = heute()
    if S['tag'] == t:
        return
    with LOCK:
        h, lk = dict(S['h']), dict(S['lk'])
        for mac in set(h) | set(S['g']):
            g = S['g'].get(mac)
            h[mac] = (h.get(mac, []) + [int(g['u']) if g else 0])[-7:]
            if g:
                lk[mac] = list(dict.fromkeys(lk.get(mac, []) + g['l']))[:40]
        # Geräte, die 7 Tage nichts gesendet haben, vergessen
        h = {m: v for m, v in h.items() if any(v) or m in S['g']}
        S = dict(leer(), seit=S.get('seit') or t, h=h, lk={m: v for m, v in lk.items() if m in h})
    log('Tageswechsel →', t)

# ---------------------------------------------------------------- Rohdaten-Archiv
class Archiv:
    def __init__(self):
        self.tag, self.f, self.seit_flush = None, None, time.time()

    def schreiben(self, zeile):
        t = heute()
        if t != self.tag:
            if self.f:
                self.f.close()
            self.tag, self.f = t, gzip.open(os.path.join(LOGDIR, t + '.log.gz'), 'ab', compresslevel=6)
        self.f.write(zeile.encode('utf-8', 'replace') + b'\n')
        if time.time() - self.seit_flush > 30:
            self.flush()

    def flush(self):
        if self.f:
            self.f.flush()
        self.seit_flush = time.time()

    def aufraeumen(self):
        grenze = (datetime.now() - timedelta(days=TAGE)).strftime('%Y-%m-%d')
        for n in os.listdir(LOGDIR):
            if n.endswith('.log.gz') and n[:10] < grenze:
                os.remove(os.path.join(LOGDIR, n))
                log('Archiv gelöscht:', n)

ARCHIV = Archiv()

# ---------------------------------------------------------------- Auswertung
def verarbeiten(zeile, absender):
    STAT['empfangen'] += 1
    STAT['absender'][absender] = STAT['absender'].get(absender, 0) + 1
    if ABSENDER and absender not in ABSENDER:
        STAT['verworfen'] += 1
        return
    zeile = zeile.strip()
    if zeile.startswith('<'):
        zeile = zeile[zeile.find('>') + 1:]
    if not zeile:
        return
    ARCHIV.schreiben(zeile)
    f = {k: v[1:-1] if v.startswith('"') else v for k, v in KV.findall(zeile)}
    S['zeilen'] += 1
    if f.get('type') == 'event':
        fortigate_audit(f)
        return
    if f.get('type') != 'traffic' or f.get('dstintfrole') != 'wan' or not f.get('srcmac'):
        return
    mac = f['srcmac'].lower()
    try:
        b = int(f['sentdelta']) if 'sentdelta' in f else int(f.get('sentbyte', 0) or 0)
    except ValueError:
        b = 0
    with LOCK:
        S['verkehr'] += 1
        g = S['g'].setdefault(mac, {'u': 0, 'l': [], 'p': {}, 'n': '', 'ip': ''})
        g['u'] += b
        c = f.get('dstcountry', '')
        if c and c != 'Reserved' and c not in g['l'] and len(g['l']) < 30:
            g['l'].append(c[:30])
        try:
            dp = int(f.get('dstport', 0))
        except ValueError:
            dp = 0
        if dp in PORTS:
            g['p'][str(dp)] = g['p'].get(str(dp), 0) + 1
        if not g['n']:
            g['n'] = SAUBER.sub('', f.get('srcname') or f.get('srchwvendor') or '').strip()[:30]
        g['ip'] = f.get('srcip', g['ip'])
        try:
            S['letzte'] = max(S['letzte'], int(f.get('eventtime', 0)) // 1_000_000_000)
        except ValueError:
            pass

FG_KONFIG = {'0100044544', '0100044545', '0100044546', '0100044547'}
FG_LOGIN = {'0100032001': 'Admin-Anmeldung erfolgreich', '0100032002': 'Admin-Anmeldung fehlgeschlagen'}
_fg_letzte = {}

def fortigate_audit(f):
    lid = f.get('logid', '')
    wer = f.get('user', '?') + (f" ({f['ui']})" if f.get('ui') else '')
    if lid in FG_KONFIG:
        objekt = f.get('cfgpath', '') + (f" {f['cfgobj']}" if f.get('cfgobj') else '')
        AUDIT.eintragen('FortiGate-Konfiguration', f"{f.get('logdesc', 'Konfiguration geändert')} ({f.get('action', '')})",
                        objekt, f.get('cfgattr') or f.get('msg', ''), wer, 'FortiGate')
    elif lid in FG_LOGIN:
        k = (lid, f.get('srcip', ''), f.get('user', ''))
        if time.time() - _fg_letzte.get(k, 0) < 600:  # Wiederholungen bündeln
            return
        _fg_letzte[k] = time.time()
        AUDIT.eintragen('FortiGate-Anmeldung', FG_LOGIN[lid], f.get('srcip', ''), f.get('msg', ''), wer, 'FortiGate')

def alarme_pruefen():
    """Gleiche Regeln wie bisher in HA: Upload-Ausreißer, auffällige Ports, neue Länder."""
    out = []
    lern_ok = S.get('seit') and datetime.strptime(S['seit'], '%Y-%m-%d') < datetime.now() - timedelta(days=2)
    with LOCK:
        gem = S['gem']
        for mac, d in S['g'].items():
            hist = S['h'].get(mac, [])
            schnitt = sum(hist) / len(hist) if len(hist) >= 3 else None
            grenze = max(500e6, 5 * schnitt) if schnitt is not None else 2e9
            k = 'up:' + mac
            if d['u'] > grenze and k not in gem:
                t = f"hat heute {round(d['u'] / 1e6)} MB ins Internet geschickt"
                if schnitt is not None:
                    t += f" – sonst im Schnitt {round(schnitt / 1e6)} MB pro Tag"
                out.append({'mac': mac, 'art': 'upload', 'push': True, 'text': t + '.'})
                gem.append(k)
            for p, n in d['p'].items():
                k = f'p:{mac}:{p}'
                if k not in gem:
                    out.append({'mac': mac, 'art': 'port', 'push': True,
                                'text': f"baut Verbindungen ins Internet über {PORTS.get(int(p), 'Port ' + p)} auf (Port {p}, {n}× heute)."})
                    gem.append(k)
            if lern_ok and mac in S['lk']:
                for c in d['l']:
                    k = f'l:{mac}:{c}'
                    if c not in S['lk'][mac] and k not in gem:
                        out.append({'mac': mac, 'art': 'land', 'push': False, 'text': f'spricht erstmals mit einem Ziel in {c}.'})
                        gem.append(k)
        S['gem'] = gem[-300:]
        for a in out:
            a['name'] = S['g'][a['mac']]['n']
    return out

def senden(nutzlast):
    if not WEBHOOK:
        return
    try:
        req = urllib.request.Request(WEBHOOK, data=json.dumps(nutzlast).encode(), headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        log('Webhook-Fehler:', e)

def stand():
    with LOCK:
        d = json.loads(json.dumps(S))
    d['stand'] = int(time.time())
    return d

# ---------------------------------------------------------------- Empfang
class UDP(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        for z in data.decode('utf-8', 'replace').splitlines():
            verarbeiten(z, addr[0])

async def tcp(reader, writer):
    ip = writer.get_extra_info('peername')[0]
    puffer = b''
    try:
        while True:
            daten = await reader.read(65536)
            if not daten:
                break
            puffer += daten
            while puffer:
                m = re.match(rb'(\d+) ', puffer)
                if m:  # RFC 6587 Octet-Counting (FortiGate „reliable“)
                    n = int(m.group(1))
                    if len(puffer) < m.end() + n:
                        break
                    verarbeiten(puffer[m.end():m.end() + n].decode('utf-8', 'replace'), ip)
                    puffer = puffer[m.end() + n:]
                elif b'\n' in puffer:
                    z, puffer = puffer.split(b'\n', 1)
                    verarbeiten(z.decode('utf-8', 'replace'), ip)
                else:
                    break
    finally:
        writer.close()

async def zyklus():
    letzter_stand = 0
    while True:
        await asyncio.sleep(60)
        try:
            tageswechsel()
            ARCHIV.flush()
            a = alarme_pruefen()
            if a:
                log('Alarme:', len(a))
                await asyncio.to_thread(senden, {'art': 'alarm', 'alarme': a})
            if time.time() - letzter_stand >= STAND_INTERVALL:
                letzter_stand = time.time()
                await asyncio.to_thread(senden, {'art': 'stand', 'daten': stand()})
                ARCHIV.aufraeumen()
            speichern()
        except Exception as e:
            log('Fehler im Zyklus:', repr(e))

# ---------------------------------------------------------------- Home Assistant: Ereignisse ins Audit-Log
HA_EREIGNISSE = ['call_service', 'mobile_app_notification_action', 'netz_nac_entscheidung', 'netz_audit',
                 'automation_reloaded', 'script_reloaded', 'lovelace_updated']
NAC_SKRIPTE = {'netzwerk_asset_sperren': ('Sperre', 'Gerät gesperrt'), 'netzwerk_asset_freigeben': ('Freigabe', 'Gerät freigegeben')}
_ha_letzte = {}

def wer_ist(ctx):
    uid = (ctx or {}).get('user_id')
    if not uid:
        return None
    return PERSONEN.get(uid, 'Benutzer ' + uid[:8])

def einmal(schluessel, sekunden=60):
    if time.time() - _ha_letzte.get(schluessel, 0) < sekunden:
        return False
    _ha_letzte[schluessel] = time.time()
    return True

def ha_ereignis(ev):
    typ, d, wer = ev.get('event_type'), ev.get('data') or {}, wer_ist(ev.get('context'))
    if typ in ('mobile_app_notification_action', 'netz_nac_entscheidung'):
        a = str(d.get('action', ''))
        if a.startswith('NAC_'):
            teile = a.split('|')
            ok = teile[0] == 'NAC_OK'
            AUDIT.eintragen('Freigabe' if ok else 'Sperre', 'Neues Gerät freigegeben' if ok else 'Neues Gerät abgelehnt',
                            teile[1] if len(teile) > 1 else '', 'per Push-Meldung' if typ.startswith('mobile') else 'über die Warteliste im Dashboard',
                            wer or 'Unbekannt')
    elif typ == 'netz_audit':
        AUDIT.eintragen(d.get('kategorie') or 'Maßnahme', d.get('titel') or 'Maßnahme', d.get('objekt', ''), d.get('details', ''),
                        d.get('wer') or wer or 'System', 'Home Assistant', d.get('ereignis_zeit'), bool(d.get('ereignis_zeit')), d.get('beleg', ''))
    elif typ in ('automation_reloaded', 'script_reloaded'):
        if einmal(typ, 30):
            AUDIT.eintragen('Konfiguration', 'Automationen gespeichert/neu geladen' if typ.startswith('auto') else 'Skripte gespeichert/neu geladen',
                            '', '', wer or 'System')
    elif typ == 'lovelace_updated':
        if str(d.get('url_path', '')).startswith('netz') and einmal('lovelace', 120):
            AUDIT.eintragen('Konfiguration', 'Dashboard geändert', d.get('url_path', ''), '', wer or 'System')
    elif typ == 'call_service' and wer:  # nur direkte Bedienung durch eine Person, nicht Automationen
        dom, srv, sd = d.get('domain'), d.get('service'), d.get('service_data') or {}
        ziele = sd.get('entity_id') or []
        ziele = [ziele] if isinstance(ziele, str) else list(ziele)
        if dom == 'script' and srv in NAC_SKRIPTE:
            k, a = NAC_SKRIPTE[srv]
            AUDIT.eintragen(k, a + ' (manuell)', sd.get('mac', ''), sd.get('name', ''), wer)
        elif dom == 'script' and srv == 'turn_on' and any(z.replace('script.', '') in NAC_SKRIPTE for z in ziele):
            v = sd.get('variables') or {}
            k, a = NAC_SKRIPTE[ziele[0].replace('script.', '')]
            AUDIT.eintragen(k, a + ' (manuell)', v.get('mac', ''), v.get('name', ''), wer)
        elif dom == 'automation' and srv in ('turn_on', 'turn_off', 'toggle', 'trigger') and any('netz' in z for z in ziele):
            t = {'turn_on': 'Automation eingeschaltet', 'turn_off': 'Automation ausgeschaltet', 'toggle': 'Automation umgeschaltet', 'trigger': 'Automation manuell ausgeführt'}[srv]
            AUDIT.eintragen('Konfiguration', t, ', '.join(ziele), '', wer)
        elif dom == 'switch' and srv in ('turn_on', 'turn_off', 'toggle') and any(('_blockiert' in z or 'netz_port_' in z) for z in ziele):
            AUDIT.eintragen('Sperre', 'Sperr-Schalter ' + {'turn_on': 'ein', 'turn_off': 'aus', 'toggle': 'umgeschaltet'}[srv], ', '.join(ziele), '', wer)

async def personen_laden(s):
    async with s.get('http://supervisor/core/api/states', headers={'Authorization': 'Bearer ' + TOKEN}) as r:
        for st in await r.json():
            if st['entity_id'].startswith('person.') and st['attributes'].get('user_id'):
                PERSONEN[st['attributes']['user_id']] = st['attributes'].get('friendly_name', st['entity_id'])

async def ha_bruecke():
    if not TOKEN:
        log('Kein SUPERVISOR_TOKEN – Home-Assistant-Ereignisse werden nicht protokolliert')
        return
    import aiohttp
    while True:
        try:
            async with aiohttp.ClientSession() as s:
                await personen_laden(s)
                async with s.ws_connect('http://supervisor/core/websocket', heartbeat=30) as ws:
                    await ws.receive_json()
                    await ws.send_json({'type': 'auth', 'access_token': TOKEN})
                    if (await ws.receive_json()).get('type') != 'auth_ok':
                        raise RuntimeError('Anmeldung an Home Assistant fehlgeschlagen')
                    await ws.send_json({'id': 99, 'type': 'config/auth/list'})
                    for i, et in enumerate(HA_EREIGNISSE, 1):
                        await ws.send_json({'id': i, 'type': 'subscribe_events', 'event_type': et})
                    log('Audit: mit Home Assistant verbunden,', len(PERSONEN), 'Personen')
                    async for m in ws:
                        if m.type != aiohttp.WSMsgType.TEXT:
                            continue
                        d = json.loads(m.data)
                        if d.get('id') == 99 and d.get('type') == 'result' and d.get('success'):
                            for b in d.get('result') or []:  # Benutzer ohne Person (z. B. Token-Benutzer) mit Namen
                                PERSONEN.setdefault(b['id'], b.get('name') or b['id'][:8])
                        elif d.get('type') == 'event':
                            try:
                                ha_ereignis(d['event'])
                            except Exception as x:
                                log('Audit-Ereignis fehlerhaft:', repr(x))
        except Exception as x:
            log('Audit: Verbindung zu Home Assistant getrennt:', repr(x))
        await asyncio.sleep(15)

def kurz(e):
    z = e.get('ereignis_zeit') or e['zeit']
    try:
        t = datetime.fromisoformat(z)
    except ValueError:
        t = None
    return {'nr': e['nr'], 'zeit': (t.strftime('%d.%m.') if len(z) == 10 else t.strftime('%d.%m. %H:%M')) if t else z[:16], 'kat': e['kategorie'], 'wer': e['wer'],
            'aktion': e['aktion'], 'objekt': e.get('objekt', '')[:60], 'nach': bool(e.get('nachgetragen'))}

async def audit_sensor():
    """Spiegelt die letzten Einträge und den Prüfstatus als sensor.netz_audit_log nach Home Assistant."""
    if not TOKEN:
        return
    import aiohttp
    tag = None
    while True:
        await asyncio.sleep(10)
        try:
            if tag and tag != heute() and AUDIT.nr:  # Tagesabschluss: Kettenkopf ins HA-Logbuch (zweiter Speicherort)
                async with aiohttp.ClientSession() as s:
                    await s.post('http://supervisor/core/api/services/logbook/log', headers={'Authorization': 'Bearer ' + TOKEN},
                                 json={'name': 'Audit-Log', 'entity_id': 'sensor.netz_audit_log',
                                       'message': f'Tagesabschluss {tag}: {AUDIT.nr} Einträge, Kettenkopf {AUDIT.letzter[:24]}'})
            tag = heute()
            if not AUDIT.geaendert:
                continue
            AUDIT.geaendert = False
            ok, n, text = AUDIT.pruefen()
            alle = AUDIT.alle()
            attr = {'friendly_name': 'Security Audit-Log', 'icon': 'mdi:clipboard-check-outline' if ok else 'mdi:clipboard-alert',
                    'kette_ok': ok, 'pruefung': text, 'kettenkopf': AUDIT.letzter[:24],
                    'eintraege': [kurz(e) for e in reversed(alle[-20:])]}
            async with aiohttp.ClientSession() as s:
                await s.post('http://supervisor/core/api/states/sensor.netz_audit_log', headers={'Authorization': 'Bearer ' + TOKEN},
                             json={'state': n, 'attributes': attr})
        except Exception as x:
            AUDIT.geaendert = True
            log('Audit-Sensor:', repr(x))

# ---------------------------------------------------------------- Suchseite (Ingress)
def suchen(text, von, bis, limit=300):
    treffer, n = deque(maxlen=limit), 0
    ARCHIV.flush()
    for name in sorted(os.listdir(LOGDIR)):
        if not name.endswith('.log.gz') or not (von <= name[:10] <= bis):
            continue
        try:
            with gzip.open(os.path.join(LOGDIR, name), 'rt', encoding='utf-8', errors='replace') as f:
                for z in f:
                    if all(t in z.lower() for t in text):
                        n += 1
                        treffer.append(z.rstrip())
        except (EOFError, OSError):
            pass  # heutige Datei wird gerade geschrieben – bis dahin gelesen
    return list(reversed(treffer)), n

CSS = """<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:14px;background:#fafafa;color:#222;max-width:1100px}
h1{font-size:18px;margin:0 0 4px}h2{font-size:15px;margin:18px 0 6px}.s{color:#666;font-size:13px}
nav{display:flex;gap:6px;margin:0 0 12px}nav a{padding:6px 12px;border-radius:16px;background:#eceff1;color:#333;text-decoration:none;font-size:14px}
nav a.on{background:#03a9f4;color:#fff}
form{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}input,button,select,textarea{font-size:15px;padding:8px;border:1px solid #ccc;border-radius:8px;font-family:inherit}
input[name=q],input[name=titel],input[name=beleg]{flex:1 1 220px}textarea{flex:1 1 100%;min-height:60px}
button,.btn{background:#03a9f4;color:#fff;border:0;padding:8px 16px;border-radius:8px;text-decoration:none;font-size:14px}
pre{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:8px;font-size:11.5px;white-space:pre-wrap;word-break:break-all}
mark{background:#fff59d}.ok{background:#e8f5e9;color:#1b5e20;padding:8px 12px;border-radius:8px;font-size:14px}
.fehler{background:#ffebee;color:#b71c1c;padding:8px 12px;border-radius:8px;font-size:14px;font-weight:600}
.e{background:#fff;border:1px solid #e0e0e0;border-radius:10px;padding:9px 12px;margin:6px 0}
.k{display:inline-block;font-size:11.5px;padding:1px 8px;border-radius:10px;background:#e3f2fd;color:#0d47a1;margin-right:6px}
.k.FortiGate-Konfiguration,.k.FortiGate-Anmeldung{background:#fff3e0;color:#e65100}.k.Sperre,.k.Vorfall{background:#ffebee;color:#b71c1c}
.k.Freigabe{background:#e8f5e9;color:#1b5e20}.a{font-weight:600;font-size:14px;margin:3px 0}.d{font-size:12.5px;color:#555;white-space:pre-wrap;word-break:break-word}
.h{font-family:monospace;font-size:11px;color:#999}details{margin:8px 0}summary{cursor:pointer;font-weight:600;font-size:14px}
</style>"""

def nav(aktiv):
    return f"<nav><a href='./' class='{'on' if aktiv == 'logs' else ''}'>Logs</a><a href='audit' class='{'on' if aktiv == 'audit' else ''}'>Audit-Log</a></nav>"

def seite_logs(p):
    q = (p.get('q', [''])[0]).strip()
    von = p.get('von', [(datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')])[0]
    bis = p.get('bis', [heute()])[0]
    dateien = sorted(n for n in os.listdir(LOGDIR) if n.endswith('.log.gz'))
    groesse = sum(os.path.getsize(os.path.join(LOGDIR, n)) for n in dateien)
    zahl = lambda x: f'{x:,}'.replace(',', '.')
    info = (f"Empfangen seit Start: {zahl(STAT['empfangen'])} Zeilen · heute {zahl(S['zeilen'])} · "
            f"Archiv: {len(dateien)} Tage, {groesse / 1e6:.0f} MB (Aufbewahrung {TAGE} Tage) · "
            f"Absender: {' / '.join(STAT['absender']) or '–'}")
    if q:
        terme = [t.lower() for t in q.split()]
        tr, n = suchen(terme, von, bis)
        ergebnis = f'{n} Treffer' + (f', die neuesten {len(tr)} angezeigt' if n > len(tr) else '')
        zeilen = '\n\n'.join(html.escape(z) for z in tr)
        for t in terme:
            zeilen = re.sub('(' + re.escape(html.escape(t)) + ')', r'<mark>\1</mark>', zeilen, flags=re.I)
    else:
        ergebnis, zeilen = 'Mehrere Begriffe = alle müssen vorkommen. Neueste Treffer zuerst.', ''
    return (f"<!doctype html><html lang=de><title>Netz-Logs</title>{CSS}<h1>Netz-Logsammler</h1>{nav('logs')}"
            f"<div class=s>{html.escape(info)}</div><form method=get>"
            f"<input name=q placeholder='Suchbegriffe, z. B. MAC, IP, Land, Port' value='{html.escape(q, True)}'>"
            f"<input type=date name=von value='{html.escape(von, True)}'><input type=date name=bis value='{html.escape(bis, True)}'>"
            f"<button>Suchen</button></form><div class=s>{ergebnis}</div><pre>{zeilen}</pre></html>")

def audit_filter(p):
    q = (p.get('q', [''])[0]).strip().lower()
    kat = p.get('kat', [''])[0]
    von, bis = p.get('von', [''])[0], p.get('bis', [''])[0]
    out = []
    for e in AUDIT.alle():
        tag = (e.get('ereignis_zeit') or e['zeit'])[:10]
        if kat and e['kategorie'] != kat or von and tag < von or bis and tag > bis:
            continue
        if q and not all(t in json.dumps(e, ensure_ascii=False).lower() for t in q.split()):
            continue
        out.append(e)
    return out

def seite_audit(p, meldung=''):
    ok, n, text = AUDIT.pruefen()
    tr = audit_filter(p)
    q, kat = p.get('q', [''])[0], p.get('kat', [''])[0]
    von, bis = p.get('von', [''])[0], p.get('bis', [''])[0]
    kats = sorted({e['kategorie'] for e in AUDIT.alle()} | set(KATEGORIEN))
    opt = lambda w, sel: ''.join(f"<option{' selected' if k == sel else ''}>{html.escape(k)}</option>" for k in w)
    qs = urllib.parse.urlencode({k: v[0] for k, v in p.items() if v and v[0]})
    karten = []
    for e in reversed(tr[-500:]):
        zeit = e['zeit'].replace('T', ' ')[:16]
        ez = f" · Ereignis: {html.escape(e['ereignis_zeit'].replace('T', ' ')[:16])}" if e.get('ereignis_zeit') else ''
        nach = ' · nachgetragen' if e.get('nachgetragen') else ''
        beleg = f"<div class=d>Beleg: {html.escape(e['beleg'])}</div>" if e.get('beleg') else ''
        karten.append(f"<div class=e><span class='k {html.escape(e['kategorie'].replace(' ', '-'))}'>{html.escape(e['kategorie'])}</span>"
                      f"<span class=s>{zeit}{ez}{nach} · {html.escape(e['wer'])} · {html.escape(e['quelle'])}</span>"
                      f"<div class=a>{html.escape(e['aktion'])}{(' – ' + html.escape(e['objekt'])) if e.get('objekt') else ''}</div>"
                      f"<div class=d>{html.escape(e.get('details', ''))}</div>{beleg}<div class=h>Nr. {e['nr']} · {e['hash'][:16]}</div></div>")
    return (f"<!doctype html><html lang=de><title>Audit-Log</title>{CSS}<h1>Security Audit-Log</h1>{nav('audit')}"
            f"<div class='{'ok' if ok else 'fehler'}'>{'✅' if ok else '⛔'} {html.escape(text)}</div>"
            + (f"<p class=ok>{html.escape(meldung)}</p>" if meldung else '') +
            "<details><summary>➕ Maßnahme dokumentieren</summary><form method=post action=audit>"
            f"<select name=kategorie>{opt(KATEGORIEN, 'Maßnahme')}</select><input name=titel required placeholder='Was wurde gemacht? (Pflicht)'>"
            "<input name=objekt placeholder='Betroffenes System/Gerät'><textarea name=details placeholder='Details, Begründung, Ergebnis'></textarea>"
            "<input name=beleg placeholder='Beleg: Ticket, Link, Dateiname'><label class=s>Durchgeführt am (leer = jetzt) "
            "<input type=datetime-local name=ereignis_zeit></label><button>Eintragen</button></form>"
            "<div class=s>Einträge können nicht geändert oder gelöscht werden – Korrekturen als neuen Eintrag erfassen.</div></details>"
            f"<form method=get action=audit><input name=q placeholder='Suche' value='{html.escape(q, True)}'>"
            f"<select name=kat><option value=''>Alle Kategorien</option>{opt(kats, kat)}</select>"
            f"<input type=date name=von value='{html.escape(von, True)}'><input type=date name=bis value='{html.escape(bis, True)}'>"
            f"<button>Filtern</button><a class=btn href='audit.csv?{html.escape(qs, True)}'>CSV-Export</a></form>"
            f"<div class=s>{len(tr)} Einträge{' (die neuesten 500 angezeigt)' if len(tr) > 500 else ''}</div>{''.join(karten)}</html>")

class UI(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def erlaubt(self):
        if self.client_address[0] not in ('172.30.32.2', '127.0.0.1'):
            self.send_error(403)
            return False
        return True

    def antwort(self, body, typ='text/html; charset=utf-8', extra=None):
        body = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(200)
        self.send_header('Content-Type', typ)
        self.send_header('Content-Length', str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def benutzer(self):
        return self.headers.get('X-Remote-User-Display-Name') or self.headers.get('X-Remote-User-Name') or ''

    def do_GET(self):
        if not self.erlaubt():
            return
        u = urllib.parse.urlparse(self.path)
        p = urllib.parse.parse_qs(u.query)
        if u.path.endswith('/api/stand'):
            self.antwort(json.dumps(stand()), 'application/json')
        elif u.path.endswith('/api/audit'):
            ok, n, text = AUDIT.pruefen()
            self.antwort(json.dumps({'kette_ok': ok, 'pruefung': text, 'eintraege': audit_filter(p)}, ensure_ascii=False), 'application/json')
        elif u.path.endswith('/audit.csv'):
            self.antwort(AUDIT.csv(audit_filter(p)), 'text/csv; charset=utf-8',
                         {'Content-Disposition': f'attachment; filename="audit-log-{heute()}.csv"'})
        elif u.path.endswith('/audit'):
            self.antwort(seite_audit(p))
        else:
            self.antwort(seite_logs(p))

    def do_POST(self):
        if not self.erlaubt():
            return
        u = urllib.parse.urlparse(self.path)
        roh = self.rfile.read(min(int(self.headers.get('Content-Length', 0) or 0), 100000)).decode('utf-8', 'replace')
        if u.path.endswith('/api/audit'):
            daten = json.loads(roh or '{}')
            out = []
            for d in (daten if isinstance(daten, list) else [daten])[:200]:  # Liste = mehrere Einträge in Reihenfolge
                e = AUDIT.eintragen(d.get('kategorie') or 'Maßnahme', d.get('titel') or d.get('aktion') or 'Maßnahme', d.get('objekt', ''),
                                    d.get('details', ''), d.get('wer') or self.benutzer() or 'System', d.get('quelle') or 'Manuell',
                                    d.get('ereignis_zeit'), bool(d.get('nachgetragen') or d.get('ereignis_zeit')), d.get('beleg', ''))
                out.append({'nr': e['nr'], 'hash': e['hash'][:16]})
            self.antwort(json.dumps(out), 'application/json')
        elif u.path.endswith('/audit'):
            f = {k: v[0].strip() for k, v in urllib.parse.parse_qs(roh).items()}
            meldung = ''
            if f.get('titel'):
                ez = f.get('ereignis_zeit') or None
                e = AUDIT.eintragen(f.get('kategorie') or 'Maßnahme', f['titel'], f.get('objekt', ''), f.get('details', ''),
                                    self.benutzer() or 'Unbekannt', 'Manuell', ez, bool(ez), f.get('beleg', ''))
                meldung = f"Eintrag Nr. {e['nr']} gespeichert."
            self.antwort(seite_audit({}, meldung))
        else:
            self.send_error(404)

async def main():
    tageswechsel()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(UDP, local_addr=('0.0.0.0', PORT))
    srv = await asyncio.start_server(tcp, '0.0.0.0', PORT)
    threading.Thread(target=ThreadingHTTPServer(('0.0.0.0', UI_PORT), UI).serve_forever, daemon=True).start()
    asyncio.create_task(ha_bruecke())
    asyncio.create_task(audit_sensor())
    log(f'Syslog auf UDP/TCP {PORT}, Suchseite auf {UI_PORT}, Aufbewahrung {TAGE} Tage, Webhook {"aktiv" if WEBHOOK else "aus"}')
    async with srv:
        await zyklus()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    finally:
        speichern()
        ARCHIV.flush()
