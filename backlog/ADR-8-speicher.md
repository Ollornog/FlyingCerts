---
id: ADR-8
type: Decision
title: Speicher — reines Go, Migrationen von Anfang an, eine Quelle fuer Zustand
status: erledigt
tags: [architektur, speicher]
created: 2026-09-19
---

## Kontext

Der Vermittler haelt Zustand: ACME-Konto, Zertifikate, Agenten, verbrauchte Bootstrap-Token,
Aufzeichnung. Cert Warden loest das mit einer SQLite-Datei — und zeigt zugleich, was daran
wehtut.

## Gelernt

- **CGO-gebundenes SQLite wird zur Last.** Cert Warden nutzt `mattn/go-sqlite3` und benennt im
  eigenen Changelog (v0.30.0) den Wunsch, davon wegzukommen. CGO kostet die einfache
  Kreuzuebersetzung — genau den Vorteil, wegen dem wir Go gewaehlt haben ([ADR-1](ADR-1-go-als-sprache.md)).
- **Migrationen gehoeren von Tag eins in ein getestetes System.** Cert Warden fuhr zwoelf
  Schemastaende handgestrickt und stellte erst 2026 auf ein Migrationspaket um. Der Umstieg
  (v0.30.0) konnte **hart fehlschlagen**, wenn Eintraege sich nur in der Gross-/Kleinschreibung
  unterschieden — mit der Ansage, vorher von Hand in der Datenbank aufzuraeumen.
- **Zwei getrennte Migrationswege sind einer zu viel.** Neben der Datenbank hatte Cert Warden
  eine eigene, handgeschriebene Versionierung der Konfigurationsdatei. Sie brach an einer
  unzitierten YAML-Zeile mit einem Nil-Zeiger-Absturz (Issue #41).

## Wahl

- **Reines Go, kein CGO** (`modernc.org/sqlite` oder gleichwertig). Statische Binaries bleiben
  statisch.
- **Ein Migrationssystem, ab dem ersten Schema**, mit Test je Migration und einem Lauf gegen
  eine Datenbank des Vorgaengerstands.
- **Konfiguration wird nicht migriert.** Sie wird gelesen, streng geprueft und bei Unbekanntem
  mit klarer Meldung abgelehnt. Kein zweiter, schwaecherer Migrationsweg.
- Abgelaufene Eintraege (verbrauchte Token, alte Aufzeichnungen) werden aufgeraeumt. Cert Warden
  und step-ca haben beide offene Issues, weil das fehlt.

## Konsequenzen

- Der Zustand liegt an genau einer Stelle; ein Backup ist eine Datei plus die Schluessel.
- Beim Bau von Zertifikatsketten und Schluesseln gilt: die Datenbank ist die Wahrheit, die
  Dateien auf der Platte sind ihr Abzug — nicht umgekehrt.
