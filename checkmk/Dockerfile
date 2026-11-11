ARG BUILD_FROM
FROM ${BUILD_FROM}

# Eigene NagVis-Symbole (Stil „Neon“, je Gerätetyp und Zustand)
COPY nagvis-iconsets/ /zenz-iconsets/

# Wrapper liest die Add-on-Optionen und startet dann den offiziellen Checkmk-Entrypoint
COPY run.sh /run-addon.sh
RUN chmod 0755 /run-addon.sh

ENTRYPOINT ["/run-addon.sh"]
