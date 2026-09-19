---
id: ADR-7
type: Decision
title: Ein abgelaufenes Agenten-Zertifikat erneuert sich nicht selbst
status: erledigt
tags: [auth, sicherheit, betrieb]
created: 2026-09-19
---

## Kontext

Der Agent weist sich per mTLS aus. Was passiert, wenn sein Zertifikat doch ablaeuft — etwa weil
der Host laenger aus war als die Laufzeit?

step-ca hat diese Frage ausgiebig durchlebt: Der Erneuerungs-Endpunkt verlangt gueltiges mTLS,
ein abgelaufenes Zertifikat kann sich also nicht mehr ausweisen. Der Wunsch nach einem
automatischen Rueckweg ist dort seit Jahren offen (certificates#177, cli#485); das Team haelt
dagegen, dass „abgelaufen = wertlos" eine tragende Annahme jeder PKI ist. Was es gibt, ist ein
ausdruecklich als Risiko markiertes Opt-in (`--allow-renewal-after-expiry`). Der Daemon hing
frueher stattdessen sinnlos in einer Erneuerungsschleife (cli#573).

## Wahl

**Kein automatischer Rueckweg.** Ein abgelaufenes Agenten-Zertifikat wird nicht erneuert; der
Agent braucht ein neues Bootstrap-Token.

## Konsequenzen

- Der Agent erneuert **frueh**: nach zwei Dritteln der Laufzeit, mit einem zufaelligen Zuschlag
  (step-ca nutzt bis zu einem Zwanzigstel der Restdauer), damit nicht die halbe Flotte
  gleichzeitig anklopft.
- Laeuft die Erneuerung ins Leere, **wiederholt der Agent mit wachsendem Abstand und meldet es
  laut** — er darf nicht still in einer Schleife haengen (cli#573) und nicht so tun, als sei
  alles in Ordnung.
- Der Zustand „abgelaufen, muss neu aufgenommen werden" ist ein **eigener, erkennbarer
  Fehlerzustand** mit klarer Handlungsanweisung, kein allgemeiner Verbindungsfehler.
- Der Vermittler sieht es kommen: Er kennt den letzten Abholzeitpunkt je Agent (M-5) und kann
  warnen, **bevor** ein Agent sich aussperrt.
