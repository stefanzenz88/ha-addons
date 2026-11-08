# Checkmk (Community)

Netzwerk- und Infrastruktur-Monitoring auf Basis des offiziellen Images `checkmk/check-mk-community`.

## Erster Start

1. Unter **Konfiguration** ein `admin_password` setzen (ohne Anführungszeichen) und speichern.
2. Add-on starten. Der erste Start dauert einige Minuten (Site `cmk` wird angelegt).
3. Weboberfläche: `http://<HA-IP>:8095/cmk/` – Benutzer `cmkadmin`.

Das Kennwort aus der Konfiguration wird nur beim ersten Anlegen verwendet. Später das Kennwort in Checkmk selbst ändern und den Wert in der Add-on-Konfiguration wieder leeren.

## Daten & Backup

- Die Site liegt im Add-on-Konfigurationsordner (`/addon_configs/…_checkmk`) und bleibt bei Updates und Neubau erhalten.
- Messwert-Historie (RRD) und Logs sind vom HA-Backup ausgenommen, die Konfiguration nicht.

## Updates

- Neue Patchversionen (z. B. 2.5.0p17 → p18) übernimmt das Repository automatisch; in HA erscheint „Update verfügbar“.
- Checkmk aktualisiert die vorhandene Site beim Start selbst.
- Neue Hauptversionen (z. B. 2.6) werden nur als GitHub-Issue gemeldet und bewusst manuell übernommen – immer nur eine Hauptversion pro Schritt.

## Hinweise

- Nur amd64 (x86) – wie das offizielle Checkmk-Image.
- Abfragen (SNMP, Ping) laufen aus dem Container ins LAN; Port 8095 nur im LAN freigeben.
