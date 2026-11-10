"""Audit-Log mit Hash-Kette: jeder Eintrag enthält den Hash des vorherigen.
Wird eine Zeile nachträglich geändert, gelöscht oder eingefügt, schlägt die Prüfung ab dieser Stelle fehl."""
import csv, hashlib, io, json, os, threading
from datetime import datetime

NULL = '0' * 64
FELDER = ['nr', 'zeit', 'ereignis_zeit', 'quelle', 'kategorie', 'wer', 'aktion', 'objekt', 'details', 'beleg', 'nachgetragen', 'vorher', 'hash']


def _hash(e):
    roh = {k: v for k, v in e.items() if k != 'hash'}
    return hashlib.sha256(json.dumps(roh, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest()


class Audit:
    def __init__(self, pfad):
        self.pfad, self.lock = pfad, threading.Lock()
        self.nr, self.letzter, self.geaendert = 0, NULL, True
        if os.path.exists(pfad):
            for e in self.alle():
                self.nr, self.letzter = e['nr'], e['hash']

    def eintragen(self, kategorie, aktion, objekt='', details='', wer='System', quelle='Home Assistant',
                  ereignis_zeit=None, nachgetragen=False, beleg=''):
        with self.lock:
            e = {'nr': self.nr + 1, 'zeit': datetime.now().astimezone().isoformat(timespec='seconds'),
                 'quelle': str(quelle)[:40], 'kategorie': str(kategorie)[:40], 'wer': str(wer or 'System')[:80],
                 'aktion': str(aktion)[:200], 'objekt': str(objekt or '')[:200], 'details': str(details or '')[:1000]}
            if ereignis_zeit:
                e['ereignis_zeit'] = str(ereignis_zeit)[:40]
            if nachgetragen:
                e['nachgetragen'] = True
            if beleg:
                e['beleg'] = str(beleg)[:300]
            e['vorher'] = self.letzter
            e['hash'] = _hash(e)
            with open(self.pfad, 'a', encoding='utf-8') as f:
                f.write(json.dumps(e, ensure_ascii=False) + '\n')
                f.flush()
                os.fsync(f.fileno())
            self.nr, self.letzter, self.geaendert = e['nr'], e['hash'], True
            return e

    def alle(self):
        if not os.path.exists(self.pfad):
            return []
        with open(self.pfad, encoding='utf-8') as f:
            return [json.loads(z) for z in f if z.strip()]

    def pruefen(self):
        """(ok, anzahl, text) – prüft Reihenfolge, Verkettung und Hash jedes Eintrags."""
        vorher, n = NULL, 0
        try:
            for n, e in enumerate(self.alle(), 1):
                if e.get('nr') != n:
                    return False, n, f'Nummer {n} fehlt oder doppelt'
                if e.get('vorher') != vorher:
                    return False, n, f'Kette bei Nr. {n} unterbrochen'
                if _hash(e) != e.get('hash'):
                    return False, n, f'Eintrag Nr. {n} wurde verändert'
                vorher = e['hash']
        except Exception as x:
            return False, n, f'Datei unlesbar ab Nr. {n + 1}: {x}'
        return True, n, f'Kette vollständig geprüft: {n} Einträge, unverändert'

    def csv(self, eintraege):
        b = io.StringIO()
        w = csv.DictWriter(b, fieldnames=FELDER, delimiter=';', extrasaction='ignore')
        w.writeheader()
        for e in eintraege:
            w.writerow(e)
        return '﻿' + b.getvalue()
