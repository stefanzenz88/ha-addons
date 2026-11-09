#!/usr/bin/env python3
"""Netz-Logsammler: empfängt FortiGate-Syslog (UDP/TCP), archiviert die Rohzeilen
tageweise komprimiert, wertet den Internet-Verkehr je Gerät aus und meldet
Stand + Alarme per Webhook an Home Assistant. Suchseite über HA-Ingress."""
import asyncio, gzip, html, json, os, re, threading, time, urllib.parse, urllib.request
from collections import deque
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OPT = json.load(open('/data/options.json')) if os.path.exists('/data/options.json') else {}
PORT = int(OPT.get('port', 5514))
WEBHOOK = OPT.get('webhook_url') or ''
TAGE = int(OPT.get('aufbewahrung_tage', 21))
ABSENDER = set(OPT.get('erlaubte_absender') or [])
STAND_INTERVALL = int(OPT.get('stand_intervall_sekunden', 300))
UI_PORT = int(OPT.get('ui_port', 8097))
LOGDIR, STATEF = '/data/logs', '/data/state.json'
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

SEITE = """<!doctype html><html lang=de><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Netz-Logsammler</title><style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:14px;background:#fafafa;color:#222}
h1{font-size:18px;margin:0 0 4px}.s{color:#666;font-size:13px}
form{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}input,button{font-size:15px;padding:8px;border:1px solid #ccc;border-radius:8px}
input[name=q]{flex:1 1 220px}button{background:#03a9f4;color:#fff;border:0;padding:8px 16px}
pre{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:8px;font-size:11.5px;white-space:pre-wrap;word-break:break-all}
mark{background:#fff59d}</style>
<h1>Netz-Logsammler</h1><div class=s>%(info)s</div>
<form method=get><input name=q placeholder="Suchbegriffe, z. B. MAC, IP, Land, Port" value="%(q)s">
<input type=date name=von value="%(von)s"><input type=date name=bis value="%(bis)s"><button>Suchen</button></form>
<div class=s>%(ergebnis)s</div><pre>%(zeilen)s</pre></html>"""

class UI(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.client_address[0] not in ('172.30.32.2', '127.0.0.1'):
            self.send_error(403)
            return
        u = urllib.parse.urlparse(self.path)
        p = urllib.parse.parse_qs(u.query)
        if u.path.endswith('/api/stand'):
            body, typ = json.dumps(stand()).encode(), 'application/json'
        else:
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
            body = (SEITE % {'info': html.escape(info), 'q': html.escape(q), 'von': html.escape(von),
                             'bis': html.escape(bis), 'ergebnis': ergebnis, 'zeilen': zeilen}).encode()
            typ = 'text/html; charset=utf-8'
        self.send_response(200)
        self.send_header('Content-Type', typ)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

async def main():
    tageswechsel()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(UDP, local_addr=('0.0.0.0', PORT))
    srv = await asyncio.start_server(tcp, '0.0.0.0', PORT)
    threading.Thread(target=ThreadingHTTPServer(('0.0.0.0', UI_PORT), UI).serve_forever, daemon=True).start()
    log(f'Syslog auf UDP/TCP {PORT}, Suchseite auf {UI_PORT}, Aufbewahrung {TAGE} Tage, Webhook {"aktiv" if WEBHOOK else "aus"}')
    async with srv:
        await zyklus()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    finally:
        speichern()
        ARCHIV.flush()
