---
id: M-4
type: Milestone
title: Agent — anfordern, ablegen, neu laden
status: offen
tags: [client]
created: 2026-09-19
---

Das Gegenstueck auf dem internen Host. Ein einzelnes Binary, das per Timer laeuft.

**Fertig, wenn wahr ist:**

- Bootstrap mit Token, danach Anforderung ausschliesslich per mTLS.
- Zertifikat wird atomar geschrieben, mit einstellbarem Eigentuemer und Rechten.
- Nach einer Erneuerung laeuft ein Hook — und der Agent **prueft, ob er gewirkt hat**
  (siehe ADR-5), statt sich auf den Rueckgabewert zu verlassen.
- Laeuft nichts Neues an, passiert nichts: kein Schreiben, kein Hook, kein Rauschen.
