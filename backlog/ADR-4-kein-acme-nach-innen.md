---
id: ADR-4
type: Decision
title: Agenten sprechen nicht ACME mit dem Vermittler
status: erledigt
tags: [architektur, acme]
created: 2026-09-19
---

## Kontext

Die nachliegende Idee: der Vermittler spielt einen ACME-Server, dann brauchen die Agenten gar
kein eigenes Programm — jeder vorhandene ACME-Client koennte gegen ihn laufen. Das waere
elegant, und es wird regelmaessig gewuenscht. Es geht aber nur eingeschraenkt.

## Warum es so nicht geht

- **Ein vorhandenes Zertifikat laesst sich nicht per ACME weiterreichen.** RFC 8555 signiert im
  `finalize`-Schritt genau den CSR, den der Client erzeugt hat. Ein Server kann kein fremdes,
  bereits ausgestelltes Zertifikat als Antwort auf einen fremden CSR ausgeben — das Ergebnis
  passte nicht zum Schluessel des Anfragenden.
- **Ein Blatt-Zertifikat kann nichts signieren.** Ein Platzhalter-Zertifikat ist keine CA (kein
  `CA:TRUE`, kein `keyCertSign`), taugt also nicht als Signierschluessel eines ACME-Servers.
- Der einzige verbleibende Weg waere, auf jede Anfrage dasselbe Zertifikat **samt privatem
  Schluessel** zurueckzugeben. Das ist der `share`-Modus mit ACME-Zeremonie obendrauf — mehr
  Aufwand, kein Gewinn.

Wer wirklich ACME nach innen sprechen will, braucht eine eigene CA (dann sind die Zertifikate
nicht oeffentlich vertrauenswuerdig) oder einen echten Registrierungsstellen-Aufbau vor einer
CA, die das unterstuetzt — Let's Encrypt gehoert nicht dazu.

## Wahl

Agenten sprechen ein eigenes, schlankes Protokoll ueber mTLS. Kein ACME-Server nach innen.

## Konsequenzen

- Auf jedem internen Host laeuft ein Agent-Binary. Das ist der Preis; er ist klein, weil das
  Binary statisch ist.
- Die README benennt das ausdruecklich unter „Was es nicht ist", damit die Frage nicht in jedem
  zweiten Issue neu gestellt wird.
- Sollte **DNS-PERSIST-01** allgemein verfuegbar werden, aendert das die Lage: dann koennte jeder
  Host mit einem dauerhaft gesetzten TXT-Eintrag selbst erneuern, ohne wiederkehrenden
  DNS-Schreibzugriff. Das waere ein Grund, diese Entscheidung neu zu bewerten — noch ist der
  Challenge-Typ nicht in Produktion.
