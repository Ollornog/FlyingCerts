---
id: M-3
type: Milestone
title: Modus `issue` — je Agent ein eigenes Zertifikat
status: offen
tags: [server, acme, csr]
created: 2026-09-19
---

Der empfohlene Betriebsmodus: der Agent erzeugt seinen Schluessel selbst, es reist nie ein
privater Schluessel.

**Fertig, wenn wahr ist:**

- Der Agent schickt einen CSR, der Vermittler beschafft dafuer ein Zertifikat und gibt es zurueck.
- **Der Vermittler prueft jeden Namen im CSR gegen das, was diesem Agenten erlaubt ist.** Ein CSR
  mit einem fremden oder zusaetzlichen Namen wird abgelehnt, nicht stillschweigend beschnitten.
- Der Vermittler kennt Ablaufdatum und Namen je Agent und kann beides ausgeben.
