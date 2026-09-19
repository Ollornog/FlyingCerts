---
id: M-2
type: Milestone
title: Aufnahme eines Agenten — Bootstrap-Token und mTLS
status: offen
tags: [auth, mtls, sicherheit]
created: 2026-09-19
---

Ein Agent kommt genau einmal mit einem Token und danach nie wieder ohne sein eigenes Zertifikat.

**Fertig, wenn wahr ist:**

- Der Vermittler stellt ein Bootstrap-Token fuer einen benannten Agenten aus: einmalig
  einloesbar, kurzlebig, an diesen Namen gebunden.
- Ein zweiter Einloeseversuch desselben Tokens schlaegt fehl — auch nebenlaeufig.
- Nach der Einloesung akzeptiert der Vermittler ausschliesslich mTLS; ein Aufruf ohne gueltiges
  Client-Zertifikat wird abgewiesen, bevor er irgendetwas bewirkt.
- Der Agent erneuert sein Client-Zertifikat rechtzeitig selbst und sperrt sich nicht aus.
- Ein Client-Zertifikat laesst sich sperren, und die Sperre wirkt sofort.
