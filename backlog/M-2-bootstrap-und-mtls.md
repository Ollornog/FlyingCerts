---
id: M-2
type: Milestone
title: Aufnahme eines Agenten — Bootstrap-Token und mTLS
status: erledigt
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

**Erledigt (2026-09-19).** Was dabei jeweils den Ausschlag gab:

- Die Einmaligkeit haengt an `os.Rename`, nicht an einem Merker — lesen-pruefen-schreiben hat
  dazwischen ein Fenster. Nachgewiesen mit 24 gleichzeitigen Einloesungen (genau ein Gewinner)
  und einem Neustart-Test.
- Der mTLS-Zwang ist nicht in die Handler geschrieben, sondern in die Registrierung: `openRoute`
  gegen `mTLSRoute`. Ein Test laeuft **jede** Route ohne Ausweis ab und prueft auf den genauen
  Wortlaut der Abweisung — eine neue Route, die jemand zu sichern vergisst, faellt dort auf und
  nicht im Betrieb. Auf den Statuscode allein zu pruefen haette nicht gereicht: `/v1/enroll`
  antwortet auf eine leere Anfrage ebenfalls mit 401.
- Der Ausweis-Name kommt aus `VerifiedChains`, nie aus einem Kopffeld. Ein Test schickt
  `X-Agent-Name` und `Authorization` mit und erwartet, dass sich nichts aendert.
- „Nicht erlaubt" und „gibt es nicht" antworten **gleich** (404), sonst kartiert ein Agent den
  Bestand des Vermittlers, indem er Namen durchprobiert.
