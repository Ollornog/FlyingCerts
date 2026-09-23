#!/usr/bin/env bash
#
# _nur_doku.sh — entscheidet, ob ein Änderungssatz AUSSCHLIESSLICH Doku berührt.
#
#   scripts/_nur_doku.sh --seit <ref> [<ziel>]   # aus `git diff <ref> <ziel|HEAD>`
#   scripts/_nur_doku.sh                         # Dateiliste auf stdin, eine je Zeile
#
# Das optionale <ziel> gibt es, damit die Suite den git-Zweig gegen ECHTE Historie
# prüfen kann (ein Doku-Commit aus der Vergangenheit muss `true` ergeben). Ohne
# einen Fall, in dem dieser Zweig `true` sagt, wäre „immer false, weil git
# scheitert" von einem funktionierenden Skript nicht zu unterscheiden. Der Workflow
# lässt das Argument weg.
#
# Gibt genau ein Wort auf stdout: `true` oder `false`. Exit immer 0 — die Antwort
# ist das Ergebnis, nicht der Exit-Code (sonst verschluckt `set -e` im Aufrufer die
# Entscheidung und macht aus „nein" einen Abbruch).
#
# ─── Wozu ──────────────────────────────────────────────────────────────────────
# Die CI lässt bei einer reinen Doku-Änderung die TEUREN Schritte weg (Go-Toolchain,
# Test-CA, `go vet`, `go test -race`) und fährt nur die Hygiene. Der Gewinn ist
# gemessen: der Job kostet 47–63 s, davon gehen Toolchain, Pebble-Container und die
# Go-Suite (zweimal, für die Wiederholbarkeit) drauf. Übrig bleiben ~10 s.
#
# **Doku ist dabei nicht „harmlos".** Eine Dienst-Subdomain, ein Heimatpfad, eine
# CT-Nummer oder ein Kundenname in einer `.md` ist genau der Verstoß, den der
# Hygiene-Test fangen soll — und der läuft im Schnellpfad WEITER. Merksatz:
# *Doku darf den Schnellpfad nehmen, weil die Hygiene mitfährt, nicht weil Doku
# ungefährlich wäre.*
#
# ─── Die Dateimenge, und warum jede Grenze so liegt ────────────────────────────
#
# DOKU (Schnellpfad erlaubt):
#
#   *.md (überall, auch CHANGELOG.md)
#       Reine Prosa; die Anwendung liest kein Markdown (nachgesehen). Was eine
#       `.md` überhaupt kaputt machen KANN, prüft die Hygiene und prüft sie
#       weiter: Versionsgleichstand, „i18n/README.de.md folgt der Struktur von
#       README.md", „backlog/README.md ist aktuell", Pflichtdateien, Namens- und
#       Adress-Sperrliste, Fremdressourcen. Genau deshalb darf CHANGELOG.md mit.
#
#   docs/**, i18n/**, backlog/**
#       Dokumentations- und Planungsbäume. Enthalten Prosa und Bilder; Bilder
#       prüft `pruefe_keine_fremdressourcen` weiter.
#
#   LICENSE
#       Text. Vorhandensein und Copyright-Zeile prüft die Hygiene weiter.
#
# KEINE DOKU (volle Suite), mit Grund:
#
#   go.mod, go.sum          Version, Abhängigkeiten, Go-Untergrenze (die CI liest
#                           `go-version-file: go.mod`) — Verhalten, nicht Prosa.
#   .gitignore              Ändern, WAS DER TEST ÜBERHAUPT SIEHT. Präzedenzfall:
#   .gitattributes          ein `export-ignore` nahm `.github/` aus `git archive`,
#                           unter ci-local fehlten damit die Workflow-Dateien, die
#                           auf SHA-Pins geprüft werden (Kit 0.14.0,
#                           pruefe_dateiliste_plausibel). Eine Datei, die den
#                           Prüfumfang verschiebt, darf ihn nicht verkürzen dürfen.
#   .github/**              Die Prüfung selbst.
#   .ci-image, .ci-allow-dirty   Steuerdateien der CI.
#   examples/**             Beispielkonfigurationen, die eine Suite lesen kann.
#   cmd/**, internal/**, tests/**, scripts/**, alles andere   Code.
#
# Im Zweifel `false`: Wer hier eine Grenze verschiebt, muss das in
# tests/test_doku_schnellpfad.py mit einem Fall belegen.
#
# ─── Fail-closed ───────────────────────────────────────────────────────────────
# Lässt sich der Umfang nicht ermitteln, ist die Antwort `false` und die volle
# Suite läuft: leere Dateiliste, fehlender/unbekannter Basis-Commit, Null-SHA
# (erster Push eines Branches), Force-Push mit weggeworfener Basis,
# workflow_dispatch ohne Basis. Ein Schnellpfad, der bei Unklarheit den kurzen Weg
# nimmt, ist kein Schnellpfad, sondern ein Loch.
#
set -euo pipefail

cd "$(dirname "$0")/.."

# Eine Datei ist Doku, wenn sie auf genau eines dieser Muster passt.
# (bash-Mustervergleich, kein Dateiglob: `*` überschreitet hier auch `/`.)
ist_doku() {
    local f="$1"
    case "$f" in
        *.md)        return 0 ;;
        docs/*)      return 0 ;;
        i18n/*)      return 0 ;;
        backlog/*)   return 0 ;;
        LICENSE)     return 0 ;;
        *)           return 1 ;;
    esac
}

# Urteil über eine Dateiliste (Zeilen in $1).
#
# Die Liste kommt als ARGUMENT, nicht über eine Pipe: `liste | urteile` läuft in
# einer Subshell, und wenn urteile beim ersten Code-Treffer aussteigt, kann der
# Schreiber SIGPIPE bekommen — unter `set -o pipefail` wird daraus Exit 141 und
# der CI-Schritt scheitert, obwohl das Urteil längst feststand.
urteile() {
    local gesehen=0 f
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        gesehen=1
        ist_doku "$f" || { echo false; return 0; }
    done <<< "${1-}"
    # Kein einziger Pfad = nichts zu entscheiden = voller Lauf.
    [[ $gesehen -eq 1 ]] && echo true || echo false
    return 0
}

if [[ "${1:-}" == "--seit" ]]; then
    basis="${2:-}"
    ziel="${3:-HEAD}"

    # Leer oder Null-SHA (GitHub schickt beim ersten Push eines Branches
    # 0000000000000000000000000000000000000000 in github.event.before).
    if [[ -z "$basis" || "$basis" =~ ^0+$ ]]; then
        echo false
        exit 0
    fi

    # Unbekannter Commit: flacher Klon (fetch-depth: 1) oder Force-Push, der die
    # alte Spitze weggeworfen hat.
    if ! git rev-parse --verify --quiet "${basis}^{commit}" >/dev/null 2>&1; then
        echo false
        exit 0
    fi

    # --no-renames ist WESENTLICH: mit Umbenennungserkennung zeigt git nur das
    # ZIEL. Ein `internal/x.go` -> `docs/x.go` sähe dann wie eine reine
    # Doku-Änderung aus, obwohl Code aus der Anwendung verschwindet.
    if ! liste="$(git diff --name-only --no-renames "$basis" "$ziel" 2>/dev/null)"; then
        echo false
        exit 0
    fi

    urteile "$liste"
    exit 0
fi

if [[ $# -gt 0 ]]; then
    echo "Aufruf: $0 [--seit <ref> [<ziel>]]   (ohne Argument: Dateiliste auf stdin)" >&2
    exit 2
fi

urteile "$(cat)"
