# Netz-Köder (Honeypot)

Der Köder öffnet auf dem Home-Assistant-Host einige Ports, die im Heimnetz
niemand benutzen sollte (FTP, Telnet, Windows-Dateifreigabe, MS-SQL, SSH auf
2222, Remote Desktop, VNC). Dahinter steckt kein echter Dienst. Verbindet sich
ein Gerät trotzdem, sucht es sehr wahrscheinlich das Netz ab – der Köder meldet
das sofort an Home Assistant.

## Einstellungen

| Option | Bedeutung |
|---|---|
| `ports` | Ports, auf denen der Köder lauscht. Belegte Ports werden übersprungen. |
| `webhook_url` | Home-Assistant-Webhook, z. B. `http://127.0.0.1:8123/api/webhook/<id>` |
| `ignore` | Quelladressen, die nie gemeldet werden (z. B. ein eigener Scanner) |
| `cooldown_seconds` | Meldepause je Quelle und Port, damit ein Scan keine Push-Flut auslöst |

Die Meldung enthält Quelladresse, Port, Dienstname und die Zahl der empfangenen
Bytes. Inhalte der Verbindung werden nur im App-Protokoll gezeigt.

Die App nutzt das Host-Netzwerk, damit die echte Quelladresse sichtbar ist.
