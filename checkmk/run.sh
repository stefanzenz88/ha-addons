#!/bin/bash
# Checkmk-Add-on: Optionen aus /data/options.json übernehmen und den offiziellen Entrypoint starten.
set -e

OPTS=/data/options.json
opt() {
  # einfacher JSON-Leser ohne jq/python (Werte ohne Anführungszeichen)
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$OPTS" 2>/dev/null | head -n1
}

export CMK_SITE_ID=cmk
TZ_OPT="$(opt timezone)"
export TZ="${TZ_OPT:-Europe/Vienna}"

PW="$(opt admin_password)"
if [ -n "$PW" ]; then
  # wird nur beim ersten Anlegen der Site verwendet; danach Kennwort in Checkmk ändern
  export CMK_PASSWORD="$PW"
fi

if [ -d "/omd/sites/${CMK_SITE_ID}/etc" ]; then
  echo "[addon] Vorhandene Site '${CMK_SITE_ID}' gefunden – Checkmk übernimmt sie (bei neuer Version automatisches Update)."
else
  echo "[addon] Keine Site vorhanden – Checkmk legt '${CMK_SITE_ID}' neu an."
  if [ -z "$PW" ]; then
    echo "[addon] Kein admin_password gesetzt – Checkmk erzeugt ein Zufallskennwort (steht im Log unten)."
  fi
fi

exec /docker-entrypoint.sh "$@"
