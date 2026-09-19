---
id: M-3
type: Milestone
title: Modus `issue` — je Agent ein eigenes Zertifikat
status: erledigt
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

**Erledigt (2026-09-20).** Die Namenspruefung sitzt in `internal/csrcheck` und ist **exakte
Mengengleichheit**, wie step-ca sie macht — nicht Teilmenge. Der zweite Teil ist der weniger
offensichtliche: eine Teilmenge zu erlauben verwandelt EINE Erlaubnis in mehrere Zertifikate im
Umlauf (a allein, b allein, beide zusammen), und niemand liest die Erlaubnis so.

**Abgelehnt statt beschnitten.** Ein Antrag mit einem Namen zu viel wird zurueckgewiesen, nicht
stillschweigend gekuerzt: sonst fragt der Aufrufer nach einem Zertifikat, bekommt ein anderes und
merkt es erst am TLS-Handshake.

Weitere Entscheidungen, die im Code begruendet stehen:

- Der **Common Name ausserhalb der SANs zaehlt mit**. Ein ignoriertes Feld ist eines, durch das
  jemand einen Namen schmuggelt.
- **IP, E-Mail und URI im Antrag werden abgelehnt.** Dieses Werkzeug stellt Zertifikate fuer
  Hostnamen aus; alles andere ist ein Versehen oder ein Versuch.
- Verglichen wird **wie DNS vergleicht** (Gross-/Kleinschreibung, abschliessender Punkt). Eine
  Pruefung, die strenger ist als die Sache, die sie schuetzt, weist identische Antraege ab.
- Die Ablehnung nennt dem Aufrufer **welcher Name** stoerte — anders als bei einem unbekannten
  Zertifikat gibt es hier nichts zu verraten, er hat die Namen ja selbst geschickt.
- Die Pruefung passiert **vor** jedem Gang zur CA. Ein abgelehnter Antrag kostet nichts und kann
  kein Rate-Limit beruehren.
