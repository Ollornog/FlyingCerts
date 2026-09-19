---
id: M-1
type: Milestone
title: Vermittler-Grundgeruest — Zertifikate holen und halten
status: offen
tags: [server, acme]
created: 2026-09-19
---

Der Vermittler laeuft als Dienst, holt per ACME/DNS-01 Zertifikate und haelt sie samt Zustand
vor. Noch ohne Clients — erst muss die Beschaffung verlaesslich sein.

**Fertig, wenn wahr ist:**

- Ein Zertifikat wird per DNS-01 beschafft und auf der Platte abgelegt (atomar, Rechte 0600).
- Erneuerung laeuft automatisch, gesteuert ueber ARI, mit Rueckfall auf einen Anteil der
  Lebensdauer, wenn die CA kein ARI anbietet.
- Der ACME-Account-Key ueberlebt einen Neustart und wird nie neu erzeugt, wenn einer da ist.
- Ein Fehlschlag beim Holen laesst das vorhandene Zertifikat unberuehrt und wird gemeldet.
