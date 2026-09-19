---
id: T-4
type: Task
title: "Ende-zu-Ende-Lauf gegen eine Test-CA (Pebble)"
status: erledigt
milestone: M-1
tags: [test, acme]
created: 2026-09-19
---

Jedes Teil des Beschaffungswegs ist für sich getestet, aber **nie am Stück gegen eine echte CA
gelaufen**. Solange das fehlt, ist M-1 nicht abgeschlossen — die Einzelteile können alle stimmen
und die Verkettung trotzdem nicht funktionieren.

**Zu tun:** [Pebble](https://github.com/letsencrypt/pebble) (die Test-CA von Let's Encrypt) samt
`pebble-challtestsrv` starten, einen Challenge-Löser dagegen einspeisen (`IssuerConfig.Provider`
gibt es genau dafür) und die volle Kette fahren: Konto anlegen → Zertifikat holen → ablegen →
laden → erneuern.

**Worauf es dabei ankommt** — das sind die Stellen, die ein Einzeltest nicht abdeckt:

- Das abgelegte Zertifikat passt zum abgelegten Schlüssel und lässt sich als TLS-Paar laden.
- Ein zweiter Lauf holt **nicht** erneut, weil nichts fällig ist.
- Die Erneuerung schickt `ReplacesCertID`; ohne das entfällt die Rate-Limit-Ausnahme aus
  RFC 9773 §5 stillschweigend, und niemand merkt es, bis das Limit greift.
- Ein Fehlschlag mitten im Vorgang lässt das vorhandene Zertifikat unangetastet.
- In der gesamten Ausgabe taucht kein Zugangsdatum auf.

**Fertig, wenn:** Der Lauf ist Teil von `scripts/check.sh` — übersprungen, wenn Pebble nicht
erreichbar ist, damit er niemanden blockiert, aber in der CI **nicht** übersprungen, sonst ist er
nur Dekoration.
