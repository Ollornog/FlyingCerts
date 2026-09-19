---
id: ADR-2
type: Decision
title: mTLS mit einmaligem Bootstrap-Token statt langlebiger API-Schluessel
status: erledigt
tags: [auth, sicherheit]
created: 2026-09-19
---

## Kontext

Ein Agent muss sich beim Vermittler ausweisen. Die verbreitete Loesung sind API-Schluessel je
Client. Sie hat zwei Schwaechen: der Schluessel ist ein langlebiges Geheimnis, das auf jedem
Host liegt und kopiert werden kann, und er sagt nur „wer den Schluessel hat", nicht „wer das
ist". Eine Aufzeichnung, die auf einem kopierbaren Geheimnis beruht, belegt wenig.

## Optionen

- **Langlebiger API-Schluessel je Agent** — einfach, universell, aber dauerhaftes Geheimnis.
- **Identitaet des Mesh-VPN** — elegant und ohne Zusatzgeheimnis, setzt aber ein Mesh voraus und
  waere fuer ein allgemein einsetzbares Werkzeug zu eng.
- **mTLS mit einmaligem Bootstrap-Token** — der Agent loest ein kurzlebiges Token genau einmal
  ein und besitzt danach ein eigenes Zertifikat.

## Wahl

mTLS mit einmaligem Bootstrap-Token.

## Konsequenzen

- Nach der Aufnahme existiert **kein geteiltes Geheimnis mehr**. Wer das Client-Zertifikat
  stiehlt, braucht auch den zugehoerigen privaten Schluessel, der den Host nie verlaesst.
- Die Aufzeichnung wird belastbar: die Identitaet stammt aus dem Zertifikat, nicht aus einer
  Angabe des Aufrufers.
- **Preis:** Der Agent kann sich aussperren, wenn sein Client-Zertifikat ablaeuft. Deshalb muss
  er es deutlich vor Ablauf selbst erneuern, und es braucht einen dokumentierten Weg zurueck
  (neues Bootstrap-Token) — siehe M-2.
- Das Token braucht Schutz gegen Wiedereinloesung; „einmalig" muss auch bei zwei gleichzeitigen
  Versuchen halten.
