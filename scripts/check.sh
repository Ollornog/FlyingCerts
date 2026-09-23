#!/usr/bin/env bash
# Das Tor vor jedem Push: Go-Tests + Repo-Hygiene + Rueckstands-Check.
#
#   scripts/check.sh           # alles
#   scripts/check.sh --fast    # ohne die langsamen Go-Tests (nur wenn es wirklich eilt)
#
# Der pre-push-Hook (.githooks/pre-push) ruft dieses Skript. Einmalig pro Klon:
#   git config core.hooksPath .githooks
#
# Warum zwei Sprachen: der Code ist Go, die Repo-Hygiene kommt aus der geteilten
# Python-Basis (`tests/_kit/`, via `repokit sync`). Beides muss gruen sein.
set -euo pipefail

cd "$(dirname "$0")/.."
FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

# ---------- Go ----------
# Go-Quellen ohne Go-Toolchain sind ein Fehler, kein Grund zum Ueberspringen: sonst meldet
# der Hook "gruen", ohne eine Zeile Code geprueft zu haben.
mapfile -t GO_DATEIEN < <(git ls-files '*.go' 2>/dev/null || true)
if [[ ${#GO_DATEIEN[@]} -gt 0 ]]; then
    command -v go >/dev/null || fail "Go-Quellen vorhanden, aber keine Go-Toolchain im PATH"

    step "gofmt — Formatierung"
    UNFORMATIERT="$(gofmt -l . 2>/dev/null || true)"
    [[ -z "$UNFORMATIERT" ]] || fail "nicht gofmt-konform:"$'\n'"$UNFORMATIERT"
    echo "  alle Dateien formatiert"

    step "go vet — verdaechtige Konstrukte"
    go vet ./... || fail "go vet"

    # -count=1 schaltet den Test-Cache ab. Ohne das meldet ein zweiter Lauf
    # "(cached)" und prueft gar nichts mehr — womit der Wiederholbarkeits-
    # Durchgang der CI zur Zierde wird, obwohl er das Gegenteil beweisen soll.
    if [[ $FAST -eq 1 ]]; then
        step "go test (kurz, --fast)"
        go test -count=1 -short ./... || fail "go test -short"
    else
        step "go test — mit Race-Detektor"
        # Der Race-Detektor gehoert hier hin, nicht in einen Sonderlauf: der Server bedient
        # mehrere Agenten gleichzeitig und teilt sich Zertifikatszustand.
        go test -count=1 -race ./... || fail "go test -race"
    fi
else
    step "Go"
    echo "  noch keine Go-Quellen — uebersprungen"
fi

# ---------- Repo-Hygiene ----------
step "Repo-Hygiene und Backlog"
PY="$(command -v python3 || true)"
[[ -n "$PY" ]] || fail "python3 fehlt (wird fuer die Hygiene-Basis gebraucht)"
"$PY" tests/run_all.py || fail "Hygiene-Suite"

# ---------- Rueckstaende ----------
step "Rueckstands-Check"
# Exit 2 = NICHT ENTSCHEIDBAR (Kit 0.20.1): der Baum war schon vor dem Lauf veraendert und
# es gibt keinen Vorher-Stand. Das muss ein skip sein, kein fail — in der CI und unter
# ci-local tritt der Fall nie auf (Baum dort per Konstruktion sauber), beim Lauf von Hand
# ist er der Normalfall. Ein Fehlalarm, den man wegklickt, hat den Waechter abgeschaltet.
rc_residue=0
scripts/_residue_check.sh check || rc_residue=$?
case "$rc_residue" in
    0) : ;;
    2) printf '\033[33m! Rueckstand nicht entscheidbar (Arbeitsbaum war vorher veraendert)\033[0m\n' ;;
    *) fail "Rueckstands-Check" ;;
esac

if [[ $FAST -eq 1 ]]; then
    printf '\n\033[33m! --fast: Race-Detektor uebersprungen. Vor dem Push einmal ohne --fast laufen lassen.\033[0m\n'
fi
printf '\n\033[32m✓ alles gruen\033[0m\n'
