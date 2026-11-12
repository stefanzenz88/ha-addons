# Netz-RADIUS

RADIUS-Server für die **MAC-Authentifizierung (MAB)** an den Switch-Ports. Geräte ohne 802.1X-Fähigkeit (Kameras, Drucker, Energiezähler …) meldet der Switch mit ihrer MAC als Benutzername an; der Server prüft, ob die MAC im Geräte-Inventar von Home Assistant **freigegeben** ist (`todo.netzwerk_gerate`: abgehakt und nicht mit ⛔ markiert).

- Abgleich mit dem Inventar jede Minute (`sync_sekunden`); Änderungen werden ohne Neustart übernommen.
- Jede Anmeldung erscheint im Sensor `sensor.netz_radius` (letzte 20, mit Switch und Port).
- Abgelehnte Geräte: einmal pro Tag Vorfall im Audit-Log (App Netz-Logsammler) und Freigabe-Push über den NAC-Ablauf (`nac_webhook_url`, Ereignis `radius`).

## Einrichtung
1. `radius_secret` setzen (langes Zufallskennwort, mindestens 24 Zeichen). Dasselbe Kennwort kommt auf die Switches.
2. `switches`: IP=Name je Switch.
3. Auf den Switches: `radius-server host 10.0.0.245 key <Secret>` und MAC-Authentifizierung auf den gewünschten Ports – siehe Projekt-Doku.

**Wichtig:** Ports von Uplinks, Home Assistant (dieser Server!), NAS und Firewall nie per RADIUS absichern. Für den Ausfall des Servers `aaa authentication mac-based chap-radius authorized` setzen, dann lassen die Switches die Geräte durch, wenn RADIUS nicht antwortet.
