# Netz-Logsammler

Empfängt das Syslog der FortiGate und macht daraus drei Dinge:

1. **Archiv:** Jede Zeile landet unter `/data/logs` – der laufende Tag als Klartext, vergangene Tage komprimiert (Standard: 21 Tage).
2. **Suche:** Seitenleiste → *Netz-Logs*. Mehrere Begriffe (MAC, IP, Land, Port …) müssen alle vorkommen; neueste Treffer zuerst.
3. **Auswertung je Gerät** (Verkehr Richtung Internet): Upload heute, Zielländer, Verbindungen über auffällige Ports, 7-Tage-Verlauf. Alle 5 Minuten geht der Stand per Webhook an Home Assistant, Alarme sofort (geprüft jede Minute).

## Security-Audit-Log
Dokumentiert Änderungen und Maßnahmen nachweisbar. Jeder Eintrag enthält den SHA-256-Hash des vorherigen; die Seite „Audit-Log“ prüft die ganze Kette bei jedem Aufruf und zeigt rot, sobald ein Eintrag verändert, entfernt oder eingeschoben wurde. Einträge werden nie geändert – Korrekturen kommen als neuer Eintrag.

Automatisch erfasst:
- FortiGate: Konfigurationsänderungen (wer, über welche Oberfläche, welcher Pfad, welche Werte) und Admin-Anmeldungen
- Home Assistant: NAC-Freigaben/-Ablehnungen (Push oder Dashboard, mit Person), manuelles Sperren/Freigeben, Sperr-Schalter, Netzwerk-Automationen ein/aus, gespeicherte Automationen, Skripte und Netzwerk-Dashboards

Manuell: Formular auf der Seite „Audit-Log“ (Name kommt aus der HA-Anmeldung) oder Event `netz_audit` mit `titel`, `kategorie`, `objekt`, `details`, `beleg`, `ereignis_zeit`.

Export: CSV (Semikolon, Excel-tauglich) mit Hash-Spalten. Täglich wird der Kettenkopf zusätzlich ins HA-Logbuch geschrieben.

## Alarmregeln
- Upload > 500 MB **und** > 5× Tagesschnitt der letzten 7 Tage; solange weniger als 3 Tage Verlauf: > 2 GB.
- Verbindung über FTP 21, SSH 22, Telnet 23, SMTP 25, NetBIOS 139, SMB 445, MS-SQL 1433, RDP 3389, VNC 5900, IRC 6667, Tor 9001/9030/9050.
- Neues Zielland nach 2 Tagen Lernzeit (ohne Push, nur Logbuch).
Jede Meldung kommt je Gerät und Anlass höchstens einmal pro Tag.

## Optionen
| Option | Bedeutung |
|---|---|
| `port` | Syslog-Port (UDP und TCP), Standard 5514 |
| `webhook_url` | Home-Assistant-Webhook, z. B. `http://127.0.0.1:8123/api/webhook/<id>` |
| `aufbewahrung_tage` | Wie lange das Archiv bleibt |
| `erlaubte_absender` | Nur Zeilen von diesen IPs werden angenommen |
| `stand_intervall_sekunden` | Wie oft der Stand an HA geht |

## FortiGate (CLI)
```
config log syslogd setting
    set status enable
    set server "10.0.0.245"
    set port 5514
    set mode udp
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic disable
    set multicast-traffic disable
    set sniffer-traffic disable
end
```
