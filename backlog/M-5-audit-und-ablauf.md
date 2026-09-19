---
id: M-5
type: Milestone
title: Aufzeichnung und Ablaufverfolgung
status: offen
tags: [audit, betrieb]
created: 2026-09-19
---

Der Grund, warum der Vermittler ueberhaupt in der Mitte steht: er weiss, wer was wann bekommen
hat — und was demnaechst ausgeht.

**Fertig, wenn wahr ist:**

- Jede Anforderung wird mit Agent, Gegenstand, Zeit und Ergebnis aufgezeichnet; die Identitaet
  stammt aus dem Client-Zertifikat, nicht aus einer Angabe des Aufrufers.
- Der Vermittler kann ausgeben, welcher Agent wann zuletzt geholt hat und wann sein Zertifikat
  ablaeuft.
- Ein Agent, der laenger nicht geholt hat, faellt auf — bevor sein Zertifikat ablaeuft.
