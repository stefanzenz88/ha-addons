# Changelog

## 1.0.0
- Erste Version: FreeRADIUS für MAC-Authentifizierung (MAB) der Aruba-Switches. Freigegebene MACs aus `todo.netzwerk_gerate` (abgehakt, nicht ⛔), Abgleich jede Minute. Ablehnungen als Vorfall ins Audit-Log und als Freigabe-Push; Sensor `sensor.netz_radius` mit den letzten Anmeldungen.
