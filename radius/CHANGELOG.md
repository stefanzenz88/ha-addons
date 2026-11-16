# Changelog

## 1.3.0
- Benutzerverwaltung mit Stammdaten in `todo.netz_radius_benutzer` (Vorname, Nachname, E-Mail, Telefon, Firma, Grund, aktiv, gültig bis) – gepflegt über die Dashboard-Karte; Kennwörter nie in HA.
- Zugangsanfrage per Formular `http://<HA-IP>:8098/anfrage` (Spam-Falle, max. 3 Anfragen/Stunde je Gerät, max. 10 offene) → Ereignis `netz_radius_anfrage` für die Freigabe-Pushes.
- Gäste: nach Freigabe automatisch erzeugtes Kennwort (14 Zeichen) per Mail, gültig `gast_kennwort_stunden` (Standard 24 h); „Neues Kennwort senden“ über das Dashboard. Gesperrte, abgelaufene und angefragte Benutzer werden nicht zugelassen.
- Neue Optionen: SMTP (`smtp_server`, `smtp_port`, `smtp_benutzer`, `smtp_passwort`, `smtp_absender`), `gast_kennwort_stunden`, `profil_url`.
- Sensor: Status, Art, Kennwort-Ablauf, letzte Anmeldung, AP und Geräte je Benutzer.

## 1.2.0
- Geräteprofile im Heimnetz unter `http://<HA-IP>:8098/`: iPhone/iPad-Konfigurationsprofil (CA + WLAN mit festem Servernamen `radius.zenz.home`, optional Benutzername, kein Kennwort), CA als `.cer` und Windows-WLAN-Profil mit Serverprüfung. Keine Zertifikatsabfrage mehr beim Verbinden, Schutz gegen gefälschte WLANs.
- Neue Optionen `profil_port` und `profil_ssid`.

## 1.1.0
- WLAN-802.1X (WPA2/WPA3-Enterprise) für UniFi: PEAP-MSCHAPv2 und TTLS-PAP, eigene CA + Server-Zertifikat `radius.zenz.home` (825 Tage, automatische Erneuerung 30 Tage vor Ablauf), CA zum Herunterladen unter `/share/netz-radius/netz-zenz-radius-ca.crt`.
- Neue Optionen `wlan_aps` (Access Points als RADIUS-Clients), `wlan_secret` (eigenes Kennwort für die APs, leer = `radius_secret`), `wlan_benutzer` (Name + Kennwort je Person).
- Getrennte virtuelle Server: `mab` für Switch-Ports, `wlan`/`wlan-inner` für WLAN – Inventar-MACs können sich nicht als WLAN-Benutzer anmelden.
- BlastRADIUS-Härtung: `message_authenticator_pflicht` (Standard an) setzt `require_message_authenticator = yes` für alle Clients.
- WLAN-Ablehnungen als Vorfall ins Audit-Log (höchstens 1× pro Stunde je Benutzer/Gerät), Sensor zeigt WLAN-Anmeldungen mit Benutzer, Gerät und AP.

## 1.0.0
- Erste Version: FreeRADIUS für MAC-Authentifizierung (MAB) der Aruba-Switches. Freigegebene MACs aus `todo.netzwerk_gerate` (abgehakt, nicht ⛔), Abgleich jede Minute. Ablehnungen als Vorfall ins Audit-Log und als Freigabe-Push; Sensor `sensor.netz_radius` mit den letzten Anmeldungen.
