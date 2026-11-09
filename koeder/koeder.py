#!/usr/bin/env python3
"""Netz-Köder (Honeypot) für das Heimnetz.

Lauscht auf Ports, die auf dem Home-Assistant-Host niemand benutzen sollte
(FTP, Telnet, SMB, RDP ...). Jeder Verbindungsversuch wird an einen
Home-Assistant-Webhook gemeldet. Es wird kein echter Dienst angeboten:
Der Köder schickt höchstens eine Begrüßungszeile, liest ein paar Bytes
und schließt die Verbindung.
"""
import asyncio
import json
import time
import urllib.request

with open("/data/options.json", encoding="utf-8") as f:
    OPT = json.load(f)

PORTS = [int(p) for p in OPT.get("ports", [])]
URL = str(OPT.get("webhook_url", "")).strip()
IGNORE = {str(i).strip() for i in OPT.get("ignore", [])}
COOLDOWN = int(OPT.get("cooldown_seconds", 300))

BANNER = {
    21: b"220 (vsFTPd 3.0.5)\r\n",
    23: b"\r\nlogin: ",
    2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
}
DIENST = {
    21: "FTP",
    23: "Telnet",
    445: "Windows-Dateifreigabe (SMB)",
    1433: "MS-SQL-Datenbank",
    2222: "SSH",
    3389: "Remote Desktop (RDP)",
    5900: "VNC-Fernsteuerung",
}

letzte = {}  # (quelle, port) -> Zeitpunkt der letzten Meldung


def log(*teile):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *teile, flush=True)


def melden(daten):
    if not URL:
        log("Kein webhook_url gesetzt - Treffer wird nur protokolliert.")
        return
    req = urllib.request.Request(
        URL,
        data=json.dumps(daten).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as fehler:  # noqa: BLE001 - Köder darf nie abstürzen
        log("Webhook-Fehler:", fehler)


async def verbindung(reader, writer, port):
    peer = writer.get_extra_info("peername")
    quelle = peer[0] if peer else "?"
    if quelle.startswith("::ffff:"):
        quelle = quelle[7:]
    daten = b""
    try:
        if port in BANNER:
            writer.write(BANNER[port])
            await writer.drain()
        try:
            daten = await asyncio.wait_for(reader.read(200), timeout=4)
        except asyncio.TimeoutError:
            pass
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass

    if quelle in IGNORE:
        return
    jetzt = time.time()
    schluessel = (quelle, port)
    if jetzt - letzte.get(schluessel, 0) < COOLDOWN:
        return
    letzte[schluessel] = jetzt
    if len(letzte) > 5000:
        for k in [k for k, t in letzte.items() if jetzt - t > COOLDOWN]:
            letzte.pop(k, None)

    vorschau = "".join(chr(b) if 32 <= b < 127 else "." for b in daten[:60])
    dienst = DIENST.get(port, "unbekannt")
    log(f"TREFFER {quelle} -> Port {port} ({dienst}) Daten={vorschau!r}")
    await asyncio.get_running_loop().run_in_executor(
        None,
        melden,
        {"quelle": quelle, "port": port, "dienst": dienst, "bytes": len(daten)},
    )


async def main():
    server = []
    for port in PORTS:
        try:
            s = await asyncio.start_server(
                lambda r, w, p=port: verbindung(r, w, p), host="0.0.0.0", port=port
            )
            server.append(s)
            log(f"Köder lauscht auf Port {port} ({DIENST.get(port, 'unbekannt')})")
        except OSError as fehler:
            log(f"Port {port} nicht verfügbar, wird übersprungen: {fehler}")
    if not server:
        log("Kein Port konnte geöffnet werden.")
    log(f"Ignorierte Adressen: {sorted(IGNORE) or '-'} · Meldepause je Quelle/Port: {COOLDOWN} s")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
