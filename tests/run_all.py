#!/usr/bin/env python3
"""Test-Runner — fuehrt alle tests/test_*.py aus.

    python3 tests/run_all.py                 # alle Suiten
    python3 tests/run_all.py test_repo.py    # nur bestimmte

Exit-Code 0 = alles gruen, 1 = mindestens ein Fehlschlag. Kein pytest noetig; die
Suiten sind eigenstaendige assert-Skripte.

Jede Suite laeuft in einem EIGENEN Wegwerf-Verzeichnis (TMPDIR/HOME/XDG_* zeigen
dorthin, danach wird geloescht). So kann kein Zustand aus einem Lauf den naechsten
beeinflussen — die Tests sind wiederholbar. Nachweis: die Suite zweimal fahren,
beide Male gruen.

Die Go-Tests faehrt `scripts/check.sh` daneben; dieser Runner deckt die
Repo-Hygiene ab, die sprachunabhaengig ist.
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def suiten(argv: list[str]) -> list[str]:
    if argv:
        return [os.path.join(HERE, a) for a in argv]
    return sorted(glob.glob(os.path.join(HERE, "test_*.py")))


def main() -> int:
    gewaehlt = suiten(sys.argv[1:])
    if not gewaehlt:
        print("keine Suiten gefunden")
        return 1

    fehler = []
    for pfad in gewaehlt:
        name = os.path.basename(pfad)
        arbeit = tempfile.mkdtemp(prefix="fc-test-")
        umgebung = dict(os.environ)
        umgebung.update({"TMPDIR": arbeit, "HOME": arbeit,
                         "XDG_CACHE_HOME": os.path.join(arbeit, "cache"),
                         "XDG_CONFIG_HOME": os.path.join(arbeit, "config"),
                         "XDG_DATA_HOME": os.path.join(arbeit, "data")})
        try:
            print(f"\n\033[1m▸ {name}\033[0m")
            lauf = subprocess.run([sys.executable, pfad], cwd=ROOT, env=umgebung)
            if lauf.returncode != 0:
                fehler.append(name)
        finally:
            shutil.rmtree(arbeit, ignore_errors=True)

    print()
    if fehler:
        print(f"\033[31m✗ fehlgeschlagen: {', '.join(fehler)}\033[0m")
        return 1
    print(f"\033[32m✓ {len(gewaehlt)} Suite(n) gruen\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
