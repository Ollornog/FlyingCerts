---
id: ADR-1
type: Decision
title: Go als Implementierungssprache
status: erledigt
tags: [architektur]
created: 2026-09-19
---

## Kontext

Gebraucht werden zwei Programme — ein Dienst auf einem exponierten Host und ein Agent, der auf
vielen internen Hosts laeuft, teils auf kleinen Containern. Der Agent muss ohne Laufzeitumgebung
auskommen: wer ein Dutzend Hosts versorgt, will dort keine Interpreter-Umgebung pflegen.

## Optionen

- **Go** — ein statisches Binary je Plattform, mTLS in der Standardbibliothek, `lego` als
  ACME-Bibliothek mit ueber 200 DNS-Anbietern und ARI-Unterstuetzung.
- **Python** — vertraut, aber der Agent braucht dann auf jedem Zielhost eine Umgebung; genau der
  Aufwand, den dieses Werkzeug abschaffen soll.
- **Rust** — technisch geeignet, aber das ACME-Oekosystem ist duenner als `lego`.

## Wahl

Go.

## Konsequenzen

- Agent und Vermittler werden als statische Binaries ausgeliefert; Installation ist Kopieren.
- Die Repo-Hygiene bleibt auf der geteilten Python-Basis (`tests/_kit/`), weil sie
  sprachunabhaengig ist. `scripts/check.sh` faehrt beides. Der Versionsgleichstand wird gegen
  `internal/version/version.go` geprueft statt gegen eine `pyproject.toml`.
- `go test -race` gehoert in den Standardlauf, nicht in einen Sonderlauf: der Vermittler bedient
  mehrere Agenten gleichzeitig und teilt sich Zertifikatszustand.
