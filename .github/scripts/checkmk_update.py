#!/usr/bin/env python3
"""Prüft Docker Hub auf neue Checkmk-Community-Patchversionen und hebt das Add-on an.

- Innerhalb derselben Hauptversion (z. B. 2.5.0pX) wird automatisch aktualisiert.
- Erscheint eine neue Hauptversion (z. B. 2.6.0p1), wird NICHT automatisch gesprungen,
  sondern nur gemeldet (GITHUB_OUTPUT major_available), weil Checkmk Hauptversionen
  nur Schritt für Schritt aktualisiert werden dürfen.
"""
import json
import os
import re
import sys
import urllib.request

REPO = "checkmk/check-mk-community"
CONFIG = "checkmk/config.yaml"
BUILD = "checkmk/build.yaml"
CHANGELOG = "checkmk/CHANGELOG.md"
TAG_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)p(\d+)$")


def tags():
    url = f"https://hub.docker.com/v2/repositories/{REPO}/tags?page_size=100"
    out = []
    for _ in range(20):
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.load(r)
        out += [t["name"] for t in data.get("results", [])]
        url = data.get("next")
        if not url:
            break
    return out


def parse(v):
    m = TAG_RE.match(v)
    return tuple(int(x) for x in m.groups()) if m else None


def main():
    cfg = open(CONFIG, encoding="utf-8").read()
    cur = re.search(r'^version:\s*"?([^"\n]+)"?', cfg, re.M).group(1)
    cur_t = parse(cur)
    if not cur_t:
        sys.exit(f"Aktuelle Version '{cur}' nicht lesbar")

    stable = sorted({parse(t) for t in tags() if parse(t)})
    same_line = [t for t in stable if t[:3] == cur_t[:3]]
    newer_line = [t for t in stable if t[:3] > cur_t[:3]]
    fmt = lambda t: f"{t[0]}.{t[1]}.{t[2]}p{t[3]}"

    gh_out = os.environ.get("GITHUB_OUTPUT", "/dev/null")
    with open(gh_out, "a") as o:
        if newer_line:
            o.write(f"major_available={fmt(max(newer_line))}\n")

    if not same_line or max(same_line) <= cur_t:
        print(f"Kein Patch-Update (aktuell {cur})")
        return
    new = fmt(max(same_line))
    print(f"Update {cur} -> {new}")

    cfg = re.sub(r'^version:.*$', f'version: "{new}"', cfg, count=1, flags=re.M)
    open(CONFIG, "w", encoding="utf-8").write(cfg)
    b = open(BUILD, encoding="utf-8").read()
    b = re.sub(rf"{re.escape(REPO)}:[^\"\s]+", f"{REPO}:{new}", b)
    open(BUILD, "w", encoding="utf-8").write(b)
    cl = open(CHANGELOG, encoding="utf-8").read() if os.path.exists(CHANGELOG) else "# Changelog\n"
    head, _, rest = cl.partition("\n")
    entry = f"\n## {new}\n\n- Checkmk Community {new} (automatisch aus Docker Hub übernommen)\n"
    open(CHANGELOG, "w", encoding="utf-8").write(head + "\n" + entry + rest)
    with open(gh_out, "a") as o:
        o.write(f"updated={new}\n")


if __name__ == "__main__":
    main()
