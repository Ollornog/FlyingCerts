"""Der Doku-Schnellpfad der CI: Urteil, Verdrahtung, Fail-closed.

Beruehrt eine Aenderung AUSSCHLIESSLICH Doku, laesst die CI Go weg — Toolchain,
`gofmt`, `go vet`, `go test -race` und die Test-CA pruefen nichts an einer Zeile
Prosa. Die Hygiene laeuft weiter. Drei Dinge muessen dafuer stimmen, und alle drei
prueft diese Suite:

1. **Das Urteil.** `scripts/_nur_doku.sh` muss jede Dateiklasse richtig einordnen —
   und im Zweifel `false` sagen. Die Grenzen und ihre Begruendung stehen im Skript;
   hier stehen die Faelle, die sie festhalten. Wer eine Grenze verschiebt, muss hier
   einen Fall dazuschreiben.
2. **Die Verdrahtung.** Ein Urteil, das kein Workflow liest, wirkt nicht. Geprueft
   wird nicht, ob die `if:`-Zeilen "da sind", sondern dass **jeder Schritt entweder
   in der begruendeten Liste der immer laufenden steht oder am Urteil haengt** — ein
   neu hinzugefuegter teurer Schritt ohne `if:` wird damit rot statt still
   mitzulaufen.
3. **Der Hygiene-Pfad laesst keine Pruefung weg.** `scripts/check.sh --nur-hygiene`
   muss die Hygiene-Suite vollstaendig fahren und den Rueckstands-Check behalten.

Warum das eine eigene Suite bekommt: Der Schnellpfad ist die einzige Stelle in
diesem Repo, an der eine Pruefung planmaessig NICHT laeuft. Ist dieses Urteil
falsch, faellt die Go-Suite aus, ohne dass etwas rot wird.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKRIPT = os.path.join(ROOT, "scripts", "_nur_doku.sh")
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "ci.yml")
URTEIL = "steps.umfang.outputs.nur_doku"


def urteil(dateien: list[str]) -> str:
    """Das Skript mit einer Dateiliste auf stdin befragen."""
    p = subprocess.run([SKRIPT], input="\n".join(dateien), cwd=ROOT,
                       capture_output=True, text=True)
    assert p.returncode == 0, f"_nur_doku.sh brach ab ({p.returncode}): {p.stderr.strip()}"
    return p.stdout.strip()


def seit(ref: str, ziel: str | None = None) -> str:
    argv = [SKRIPT, "--seit", ref] + ([ziel] if ziel else [])
    p = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 0, f"_nur_doku.sh --seit brach ab ({p.returncode})"
    return p.stdout.strip()


# ---------------------------------------------------------------------------
# 1. Das Urteil
# ---------------------------------------------------------------------------
# Doku — darf den Schnellpfad nehmen, WEIL die Hygiene mitfaehrt.
DOKU = [
    "README.md",
    "CHANGELOG.md",
    "docs/betrieb.md",
    "docs/bild.png",
    "i18n/README.de.md",
    "backlog/M-1-durchstich.md",
    "LICENSE",
    "cmd/flying-certs-server/README.md",   # eine README bleibt Prosa, auch neben Code
]
for name in DOKU:
    assert urteil([name]) == "true", f"sollte Doku sein: {name}"
print(f"  {len(DOKU)} Doku-Klassen richtig erkannt")

# Keine Doku — volle Suite. Jeder Eintrag mit dem Grund, der im Skript steht.
CODE = [
    ("cmd/flying-certs-server/main.go", "Anwendungscode"),
    ("internal/version/version.go", "haelt die Version, die der CHANGELOG spiegelt"),
    ("go.mod", "Abhaengigkeiten und Go-Untergrenze (die CI liest go-version-file)"),
    ("go.sum", "Pruefsummen der Abhaengigkeiten"),
    ("examples/config.yaml", "Beispielkonfiguration, die eine Suite lesen kann"),
    ("examples/systemd/flying-certs-server.service", "Betriebsvorlage"),
    ("tests/test_repo.py", "die Pruefung selbst"),
    ("tests/_kit/hygiene.py", "die Pruefung selbst"),
    ("scripts/check.sh", "das Tor selbst"),
    ("scripts/_nur_doku.sh", "das Urteil selbst"),
    (".githooks/pre-push", "das lokale Netz"),
    (".gitignore", "verschiebt, WAS der Test sieht"),
    (".gitattributes", "export-ignore nahm schon einmal .github/ aus der Dateiliste"),
    (".github/workflows/ci.yml", "die Pruefung selbst"),
    (".github/dependabot.yml", "Automatik, keine Prosa"),
]
for name, grund in CODE:
    assert urteil([name]) == "false", f"darf NICHT Doku sein ({grund}): {name}"
print(f"  {len(CODE)} Code-Klassen richtig ausgeschlossen")

# Ein einziger Code-Treffer kippt den ganzen Satz.
assert urteil(["README.md", "docs/betrieb.md", "internal/x.go"]) == "false"
assert urteil(["README.md", "CHANGELOG.md", "i18n/README.de.md", "go.mod"]) == "false"
assert urteil(["README.md", "i18n/README.de.md", "docs/betrieb.md"]) == "true"
print("  gemischte Saetze: eine Code-Datei genuegt fuer die volle Suite")


# ---------------------------------------------------------------------------
# 2. Fail-closed: wer nicht weiss, faehrt voll
# ---------------------------------------------------------------------------
assert urteil([]) == "false", "leere Dateiliste muss die volle Suite ausloesen"
assert urteil(["", "", ""]) == "false", "nur Leerzeilen muss die volle Suite ausloesen"

# Die Wege, auf denen GitHub keine brauchbare Basis liefert.
FAIL_CLOSED = [
    ("", "workflow_dispatch ohne Basis"),
    ("0" * 40, "Null-SHA beim ersten Push eines Branches"),
    ("deadbeef" * 5, "unbekannter Commit (flacher Klon, Force-Push)"),
    ("kein-ref-1234", "Unsinn als Ref"),
    ("HEAD", "leerer Diff"),
]
for ref, fall in FAIL_CLOSED:
    assert seit(ref) == "false", f"fail-closed verletzt: {fall}"
print(f"  {len(FAIL_CLOSED)} Fail-closed-Faelle halten")


# Der git-Zweig muss auch "true" sagen KOENNEN. Ohne diesen Fall waere "immer false,
# weil git scheitert" von einem funktionierenden Skript nicht zu unterscheiden — und
# alle Pruefungen darueber waeren gruen, ohne etwas zu belegen.
def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT,
                          capture_output=True, text=True).stdout


def _finde_commit(nur_doku: bool) -> str | None:
    for sha in _git("log", "-n", "300", "--format=%H", "--no-merges").split():
        dateien = [f for f in _git("diff", "--name-only", "--no-renames",
                                   f"{sha}~1", sha).splitlines() if f]
        if not dateien:
            continue
        ist = all(re.search(r"\.md$|^docs/|^i18n/|^backlog/|^LICENSE$", f) for f in dateien)
        if ist is nur_doku:
            return sha
    return None


_doku = _finde_commit(nur_doku=True)
if _doku:
    assert seit(f"{_doku}~1", _doku) == "true", \
        f"echter Doku-Commit {_doku[:8]} muesste den Schnellpfad nehmen"
    print(f"  echter Doku-Commit {_doku[:8]} nimmt den Schnellpfad")
else:
    print("  skip: kein reiner Doku-Commit in den letzten 300 Commits")

_code = _finde_commit(nur_doku=False)
if _code:
    assert seit(f"{_code}~1", _code) == "false", \
        f"echter Code-Commit {_code[:8]} muesste die volle Suite ausloesen"
    print(f"  echter Code-Commit {_code[:8]} loest die volle Suite aus")
else:
    print("  skip: kein Code-Commit in den letzten 300 Commits")


# Umbenennung — der gefaehrlichste Randfall, und der einzige, den man NUR durch
# Ausfuehren erwischt: git zeigt mit Umbenennungserkennung nur das ZIEL. Ohne
# `--no-renames` saehe `internal/x.go` -> `docs/x.go` wie eine reine Doku-Aenderung
# aus, obwohl Code aus der Anwendung verschwindet.
#
# Geprueft wird im WEGWERF-REPO, nicht am Dateitext: Ein `"--no-renames" in text`
# bleibt gruen, solange das Wort noch im Kommentar darueber steht — genau so hat
# diese Pruefung in DashMyBoard ihre erste Mutation ueberlebt.
def _umbenennungs_probe() -> str:
    import shutil
    import tempfile

    g = ["git", "-c", "user.email=t@example.com", "-c", "user.name=Test",
         "-c", "core.hooksPath=", "-c", "commit.gpgsign=false"]
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "scripts"))
        os.makedirs(os.path.join(d, "internal"))
        shutil.copy2(SKRIPT, os.path.join(d, "scripts", "_nur_doku.sh"))
        with open(os.path.join(d, "internal", "x.go"), "w", encoding="utf-8") as fh:
            fh.write("package internal\n")
        subprocess.run([*g, "init", "-q"], cwd=d, check=True)
        subprocess.run([*g, "add", "-A"], cwd=d, check=True)
        subprocess.run([*g, "commit", "-qm", "start"], cwd=d, check=True)
        os.makedirs(os.path.join(d, "docs"))
        subprocess.run([*g, "mv", "internal/x.go", "docs/x.go"], cwd=d, check=True)
        subprocess.run([*g, "commit", "-qm", "verschiebe Code nach docs/"], cwd=d, check=True)
        p = subprocess.run([os.path.join(d, "scripts", "_nur_doku.sh"),
                            "--seit", "HEAD~1", "HEAD"],
                           cwd=d, capture_output=True, text=True)
        assert p.returncode == 0, f"Probe brach ab: {p.stderr.strip()}"
        return p.stdout.strip()


assert _umbenennungs_probe() == "false", \
    "Code nach docs/ verschoben darf nicht wie Doku aussehen (--no-renames fehlt?)"
print("  Umbenennung taeuscht nicht: Code nach docs/ ⇒ volle Suite")


# ---------------------------------------------------------------------------
# 3. Die Verdrahtung im Workflow
# ---------------------------------------------------------------------------
# Grobparser fuer unsere Schreibweise: Jobs auf Einrueckung 2, Schritte als
# '      - ' (6 Leerzeichen). Findet er nichts, ist der Anker weg — dann MUSS die
# Suite rot werden und eine neue Quelle verlangen, statt still durchzuwinken.
JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
SCHRITT = re.compile(r"^      - ")


def schritte_je_job(text: str) -> dict[str, list[str]]:
    jobs: dict[str, list[str]] = {}
    job = None
    offen = False
    for line in text.splitlines():
        m = JOB.match(line)
        if m and not line.startswith("    "):
            job, offen = m.group(1), False
            jobs[job] = []
            continue
        if job is None:
            continue
        if SCHRITT.match(line):
            jobs[job].append(line)
            offen = True
            continue
        if offen and (line.startswith("        ") or not line.strip()):
            jobs[job][-1] += "\n" + line
            continue
        if line.strip() and not line.startswith("    "):
            job, offen = None, False
    return jobs


with open(WORKFLOW, encoding="utf-8") as fh:
    WF = fh.read()
JOBS = schritte_je_job(WF)

assert "test" in JOBS, f"Workflow-Parser findet den Job 'test' nicht: {sorted(JOBS)}"
assert len(JOBS["test"]) >= 6, f"Parser findet nur {len(JOBS['test'])} Schritte — Anker weg?"
print(f"  Workflow-Parser: Job 'test' mit {len(JOBS['test'])} Schritten")

# Schritte, die IMMER laufen — mit Grund. Alles andere muss am Urteil haengen.
IMMER = {
    "actions/checkout": "ohne Klon gibt es nichts zu pruefen",
    "Umfang der Aenderung": "faellt das Urteil",
}

ungebunden = []
for jobname, bloecke in JOBS.items():
    for b in bloecke:
        m = re.search(r"^      - (?:name|uses):\s*(.+)$", b, re.M)
        kennung = m.group(1).split("#")[0].strip().strip("\"'") if m else ""
        kurz = kennung.split("@")[0]
        if any(kurz.startswith(k) or kennung.startswith(k) for k in IMMER):
            continue
        if re.search(r"^\s+if:.*" + re.escape(URTEIL), b, re.M):
            continue
        ungebunden.append(f"{jobname}: {kennung or '<ohne Namen>'}")

assert not ungebunden, ("Schritte, die weder begruendet immer laufen noch am Urteil "
                        f"haengen: {ungebunden}")
print("  jeder Schritt laeuft entweder immer (begruendet) oder haengt am Urteil")

# Die teuren Schritte namentlich — der Test soll auch dann etwas sagen, wenn jemand
# die Liste IMMER erweitert, statt den Schritt zu binden.
for name in ("actions/setup-go", "Test-CA starten (Pebble)", "Volle Suite",
             "Zweiter Lauf — Wiederholbarkeit"):
    treffer = [b for bl in JOBS.values() for b in bl if name in b]
    assert treffer, f"teurer Schritt nicht gefunden: {name}"
    assert any(re.search(r"if:.*" + re.escape(URTEIL) + r"\s*!=\s*'true'", b)
               for b in treffer), f"teurer Schritt haengt nicht am Urteil: {name}"
print("  Go-Toolchain, Test-CA und beide Suite-Laeufe haengen am Urteil")

# ... und die Hygiene laeuft im Schnellpfad WIRKLICH, nicht nur "nicht ausgeschlossen".
#
# ZWEIMAL, nicht einmal: Der teure Pfad beweist die Wiederholbarkeit mit einem zweiten
# Lauf ("ein Test, der beim zweiten Lauf rot wird, ist kaputt"). Faellt dieser Beweis
# im Schnellpfad weg, gilt die Zusage fuer Doku-Aenderungen nicht mehr — und genau das
# faellt sonst niemandem auf. Die Zahl ist der Grund, warum hier `== 2` steht und nicht
# `any(...)`: mit `any` bleibt das Loeschen eines der beiden Schritte unentdeckt.
_hygiene_schritte = [b for bl in JOBS.values() for b in bl
                     if "--nur-hygiene" in b
                     and re.search(r"if:.*" + re.escape(URTEIL) + r"\s*==\s*'true'", b)]
assert len(_hygiene_schritte) == 2, (
    "die Hygiene muss im Schnellpfad ZWEIMAL laufen (Wiederholbarkeit), gefunden: "
    f"{len(_hygiene_schritte)}")
print("  Hygiene laeuft im Schnellpfad, und zwar zweimal")

assert "fetch-depth: 0" in WF, \
    "ohne volle Historie scheitert der Diff und der Schnellpfad greift nie"
assert "_nur_doku.sh --seit" in WF, "Workflow ruft das Urteil nicht auf"
assert os.stat(SKRIPT).st_mode & 0o111, "scripts/_nur_doku.sh ist nicht ausfuehrbar"
print("  fetch-depth, Aufruf und Ausfuehrbarkeit stimmen")


# ---------------------------------------------------------------------------
# 4. Der Hygiene-Pfad laesst keine Pruefung weg
# ---------------------------------------------------------------------------

# Gegenprobe durch AUSFUEHRUNG, nicht durch Lesen. Der Marker bricht die Rekursion:
# `check.sh --nur-hygiene` faehrt run_all, und run_all faehrt DIESE Suite.
#
# Warum ausgefuehrt und nicht gelesen: Hier stand zuerst ein Textvergleich
# (`CHECK.index("Rueckstands-Check") < CHECK.index(...)`) — er war WIRKUNGSLOS, weil
# "Rueckstands-Check" schon in der Kopfzeile des Skripts steht und `index()` diese
# erste Fundstelle nimmt. Die Mutation "exit 0 vor den Rueckstands-Block ziehen"
# blieb gruen. Was zaehlt, ist nicht, dass ein Wort in der Datei steht, sondern dass
# der Block LAEUFT.
if os.environ.get("SCHNELLPFAD_IM_UNTERLAUF") == "1":
    print("  skip: Gegenprobe laeuft bereits im verschachtelten Lauf")
else:
    p = subprocess.run([os.path.join(ROOT, "scripts", "check.sh"), "--nur-hygiene"],
                       cwd=ROOT, capture_output=True, text=True,
                       env={**os.environ, "SCHNELLPFAD_IM_UNTERLAUF": "1"})
    assert p.returncode == 0, f"check.sh --nur-hygiene rot:\n{p.stdout[-800:]}"
    assert "Repo-Hygiene gruen" in p.stdout, \
        f"der Schnellpfad fuhr die Hygiene-Suite nicht:\n{p.stdout[-800:]}"
    for verboten in ("go vet", "go test", "gofmt"):
        assert verboten not in p.stdout, f"der Schnellpfad fuhr doch Go ({verboten})"

    # Der Schnellpfad darf den Rueckstands-Check nicht verlieren: ein Test, der
    # schreibt, ist auch auf dem kurzen Weg nicht wiederholbar. Die Ueberschrift des
    # Schritts erscheint nur, wenn der Block tatsaechlich ausgefuehrt wurde.
    assert "▸ Rueckstands-Check" in p.stdout, \
        f"der Schnellpfad steigt vor dem Rueckstands-Check aus:\n{p.stdout[-800:]}"
    print("  check.sh --nur-hygiene: Hygiene gruen, kein Go, Rueckstands-Check gelaufen")


print("\n\033[32m✓ Doku-Schnellpfad gruen\033[0m")
