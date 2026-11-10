# Changelog

## 1.1.3
- Fix: Websocket-IDs aufsteigend (Abos wurden in 1.1.2 abgelehnt).

## 1.1.2
- Benutzer ohne Person (z. B. Token-Benutzer) werden mit ihrem HA-Namen protokolliert; nachgetragene Einträge ohne Uhrzeit zeigen nur das Datum.

## 1.1.1
- `POST /api/audit` nimmt auch eine Liste von Einträgen an (Nachtragen in einem Schritt).

## 1.1.0
- Security-Audit-Log mit Hash-Kette (`/data/audit.jsonl`): jede Änderung an einem Eintrag, jede Lücke und jede Einfügung wird bei der Prüfung erkannt.
- Quellen: FortiGate-Konfigurationsänderungen und Admin-Anmeldungen (Syslog), NAC-Entscheidungen per Push oder Dashboard, manuelles Sperren/Freigeben, Ein-/Ausschalten von Netzwerk-Automationen, gespeicherte Automationen/Skripte/Dashboards, manuell dokumentierte Maßnahmen (Event `netz_audit` oder Formular).
- Seite „Audit-Log“ mit Filter, CSV-Export und Prüfstatus; Sensor `sensor.netz_audit_log` mit den letzten 20 Einträgen; täglicher Kettenkopf ins HA-Logbuch.

## 1.0.0
- Erste Version: Syslog-Empfang (UDP und TCP, auch „reliable“ mit Octet-Counting), Archiv je Tag komprimiert, Auswertung je Gerät (Upload, Zielländer, auffällige Ports), Webhook an Home Assistant, Suchseite über die Seitenleiste.
