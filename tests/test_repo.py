"""Repo-Hygiene: was ein Fremder sieht, wenn er das Projekt oeffnet.

Prueft, was man beim Aufraeumen zuverlaessig vergisst — Versionen, die auseinanderlaufen; Reste
im Repo; Geheimnisse; per Tag statt SHA gepinnte Actions; Uebersetzungen, die still veralten.
Kein Netz, keine Abhaengigkeiten, laeuft ueberall.

Die allgemeinen Pruefungen und die Sperrlisten stehen in `tests/_kit/` — einer geteilten,
eingecheckten Basis, die `repokit sync` hierher schreibt. Was hier steht, gilt nur fuer dieses
Projekt.

**Go-Besonderheit:** Das Kit ist fuer Python-Repos gebaut und prueft den Versionsgleichstand
gegen `pyproject.toml`. Dieses Repo hat keins — die Version steht in
`internal/version/version.go`. Der Gleichstand gegen den CHANGELOG wird deshalb hier selbst
geprueft, nicht ueber `hygiene.pruefe_versionsgleichstand`.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _kit import backlog, hygiene  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = hygiene.lade_policy()
PROJEKTE = ["flying-certs"]


def read(*parts) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


FILES = hygiene.getrackte_dateien(ROOT)

# ---------- Version: version.go und CHANGELOG muessen zusammenpassen ----------
# Go-Variante des Kit-Checks (siehe Modul-Docstring).
gv = re.search(r'^const Version = "([^"]+)"', read("internal", "version", "version.go"), re.M)
assert gv, "internal/version/version.go nennt keine Version"
version = gv.group(1)
assert re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", version), f"keine SemVer: {version}"

changelog = read("CHANGELOG.md")
veroeffentlicht = re.findall(r"^## \[(\d+\.\d+\.\d+[^\]]*)\]", changelog, re.M)
if veroeffentlicht:
    assert veroeffentlicht[0] == version, \
        f"version.go={version}, oberster CHANGELOG-Eintrag={veroeffentlicht[0]}"
    print(f"  Version {version}: version.go = CHANGELOG")
else:
    # Vor dem ersten Release steht nur [Unreleased] im CHANGELOG — dann ist nichts abzugleichen.
    assert "## [Unreleased]" in changelog, "CHANGELOG hat weder Release noch [Unreleased]"
    print(f"  Version {version} (noch kein Release; CHANGELOG hat [Unreleased])")

# ---------- Pflichtdateien ----------
PFLICHT = ["LICENSE", "README.md", "i18n/README.de.md", "CHANGELOG.md",
           "SECURITY.md", "i18n/SECURITY.de.md",
           "CODE_OF_CONDUCT.md", "i18n/CODE_OF_CONDUCT.de.md",
           "CONTRIBUTING.md", "i18n/CONTRIBUTING.de.md",
           ".gitignore", ".github/dependabot.yml",
           ".github/workflows/ci.yml", ".github/workflows/release.yml",
           "go.mod", "internal/version/version.go",
           "scripts/check.sh", "scripts/_residue_check.sh", "scripts/_backlog.py",
           "tests/run_all.py", "tests/_kit/hygiene.py", "tests/_kit/backlog.py",
           "backlog/README-KONVENTION.md"]
fehlend = hygiene.pruefe_pflichtdateien(ROOT, PFLICHT)
assert not fehlend, f"Pflichtdateien fehlen: {fehlend}"
print(f"  {len(PFLICHT)} Pflichtdateien vorhanden")

# ---------- Keine private Infrastruktur, keine Geheimnisse, keine Artefakte ----------
# Das ist bei DIESEM Projekt besonders heikel: es beschreibt eine Zertifikats-Verteilung,
# also genau die Art Aufbau, aus der man ein Netz kartieren koennte. Beispiele gehoeren auf
# `example.com`, nie auf echte Namen.
treffer = hygiene.pruefe_private_infrastruktur(ROOT, FILES, POLICY, PROJEKTE)
assert not treffer, f"private Infrastruktur im Repo: {treffer}"

treffer = hygiene.pruefe_geheimnisse(ROOT, FILES, POLICY)
assert not treffer, f"moegliche Geheimnisse im Repo: {treffer}"

treffer = hygiene.pruefe_artefakte(FILES, POLICY)
assert not treffer, f"Artefakte eingecheckt: {treffer}"
print("  keine private Infrastruktur, keine Geheimnisse, keine Artefakte")

# ---------- Echte Schluessel duerfen nie ins Repo ----------
# Der Geheimnis-Check des Kits faengt PEM-Bloecke bereits; hier zusaetzlich die Endungen,
# damit ein Testschluessel nicht versehentlich mitwandert.
schluessel = [f for f in FILES if f.endswith((".pem", ".key", ".crt", ".p12", ".pfx"))]
assert not schluessel, f"Schluessel-/Zertifikatsdateien im Repo: {schluessel}"
print("  keine Schluessel- oder Zertifikatsdateien eingecheckt")

# ---------- Workflows: SHA-gepinnt, Rechte gesetzt, kein self-hosted Runner ----------
treffer = hygiene.pruefe_actions_sha_gepinnt(ROOT, FILES)
assert not treffer, f"Actions nicht per SHA gepinnt: {treffer}"

treffer = hygiene.pruefe_workflow_permissions(ROOT, FILES)
assert not treffer, f"Workflow ohne permissions: {treffer}"

treffer = hygiene.pruefe_kein_self_hosted_runner(ROOT, FILES)
assert not treffer, f"self-hosted Runner in oeffentlichem Repo: {treffer}"
print("  Workflows: SHA-gepinnt, permissions gesetzt, ubuntu-latest")

# ---------- CHANGELOG folgt Keep a Changelog ----------
treffer = hygiene.pruefe_changelog_kategorien(ROOT, POLICY)
assert not treffer, f"CHANGELOG: {treffer}"
print("  CHANGELOG: Keep-a-Changelog-Kategorien")

# ---------- Uebersetzungen haben dieselbe Gestalt wie das Original ----------
PAARE = [("README.md", "i18n/README.de.md"),
         ("SECURITY.md", "i18n/SECURITY.de.md"),
         ("CONTRIBUTING.md", "i18n/CONTRIBUTING.de.md")]
treffer = hygiene.pruefe_uebersetzungs_struktur(ROOT, PAARE)
assert not treffer, f"Uebersetzung weicht ab: {treffer}"
print(f"  {len(PAARE)} Uebersetzungspaare strukturgleich")

# ---------- Die englische CODE_OF_CONDUCT.md muss PUR bleiben ----------
# GitHubs Community-Detektor gleicht die Datei gegen die Contributor-Covenant-Vorlage ab und
# vertraegt KEINEN Fremdinhalt — auch keinen am Ende. Sonst steht im Community-Profil
# `key: "other"` statt `contributor_covenant`. Die deutsche Fassung darf das Layout tragen.
coc = read("CODE_OF_CONDUCT.md")
for verboten in ("<img", "<p align", "Deutsch", "+++"):
    assert verboten not in coc, \
        f"CODE_OF_CONDUCT.md (EN) muss pur bleiben, enthaelt aber {verboten!r}"
assert coc.lstrip().startswith("# Contributor Covenant Code of Conduct")
assert "flying-certs-github@ollornog.de" in coc, "CoC nennt keine Kontaktadresse"
print("  CODE_OF_CONDUCT.md (EN) ist pur, Kontakt gesetzt")

# ---------- Backlog ----------
for v in backlog.alle_pruefungen(ROOT):
    raise AssertionError(f"Backlog: {v}")
eintraege = backlog.lade(ROOT)
assert eintraege, "Backlog ist leer — mindestens ein Milestone gehoert hinein"
lauf = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "_backlog.py"),
                       "index", "--dry-run"], cwd=ROOT, capture_output=True)
assert lauf.returncode == 0, f"backlog index --dry-run fehlgeschlagen: {lauf.stderr.decode()[:300]}"
print(f"  Backlog: {len(eintraege)} Eintraege, Index generierbar")

# ---------- scripts/check.sh ist ausfuehrbar ----------
treffer = hygiene.pruefe_ausfuehrbar(ROOT, ["scripts/check.sh", "scripts/_residue_check.sh"])
assert not treffer, f"nicht ausfuehrbar: {treffer}"
print("  scripts/check.sh ausfuehrbar")

# ---------- Was das Kit noch mitbringt und hier bis 2026-09-22 ungenutzt lag ----------
# Nachgezählt beim Bau des Aufruf-Waechters (repokit 0.13.0): von 17 ausgelieferten
# Pruefungen rief dieses Repo 10. Die fehlenden sieben waren kein Verzicht, sondern
# nie nachgezogen — und nichts hat es gemerkt.

# Erlaubt sind neben den neutralen Beispieladressen nur: die Badge-Quelle, die
# Pflicht-Attribution des Logos (Flaticon-Lizenz) und die ACME-Verzeichnisse von
# Let's Encrypt — letztere sind die Funktion dieses Programms, nicht eine
# Erwaehnung: ein ACME-Client ohne Verzeichnis-URL ist keiner. Sie sind zudem
# oeffentliche Infrastruktur und verraten nichts ueber das eigene Netz.
treffer = hygiene.pruefe_adressen(ROOT, FILES, POLICY,
                                  zusaetzliche_hosts=[r"img\.shields\.io",
                                                      r"(www\.)?flaticon\.com",
                                                      r"acme(-staging)?-v02\.api\.letsencrypt\.org"])
assert not treffer, f"nicht-neutrale Adresse in Doku/Code: {treffer}"
print("  nur neutrale Beispieladressen")

treffer = hygiene.pruefe_run_all_sammelt_automatisch(ROOT)
assert not treffer, f"run_all.py: {treffer}"
print("  run_all.py findet die Suiten automatisch")

# Der Schaden ist gemessen: paperlaiss verlor am 2026-09-21 vier main-Laeufe in
# 33 Sekunden. An einem abgebrochenen main-Lauf haengt hinterher kein Abbild.
treffer = hygiene.pruefe_kein_abbruch_auf_default_branch(ROOT, FILES)
assert not treffer, f"cancel-in-progress auf main: {treffer}"
print("  kein unbedingtes cancel-in-progress auf main")

# ---------- Der Waechter ueber den Waechtern ----------
# Er meldet jede Kit-Pruefung, die ausgeliefert, aber nicht gerufen wird. Die vier
# Ausnahmen unten sind die Python-Annahmen des Kits — dies ist ein Go-Repo. Sie
# stehen hier MIT Grund, damit aus "passt hier nicht" kein stilles Weglassen wird.
treffer = hygiene.pruefe_kit_prueffunktionen_gerufen(ROOT, ausgenommen={
    "pruefe_python_matrix":
        "Go-Repo: ci.yml nutzt go-version-file, es gibt keine Python-Matrix",
    "pruefe_requires_python":
        "Go-Repo: kein pyproject.toml, in dem requires-python stehen koennte",
    "pruefe_python_matrix_regel":
        "ohne eigene Python-Matrix traegt dieses Repo die Rolling-Entscheidung nicht mit",
    "pruefe_versionsgleichstand":
        "die Version steht in internal/version/version.go, nicht in pyproject.toml — "
        "der Gleichstand gegen den CHANGELOG wird oben in dieser Datei selbst geprueft",
})
assert not treffer, f"Kit-Pruefung ungerufen: {treffer}"
print("  jede Kit-Pruefung wird gerufen oder ist begruendet ausgenommen")


print("\n\033[32m✓ Repo-Hygiene gruen\033[0m")
