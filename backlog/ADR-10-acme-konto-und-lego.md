---
id: ADR-10
type: Decision
title: Ein ACME-Konto, dauerhaft gespeichert — und lego mit eigenen Zeitgrenzen
status: erledigt
tags: [acme, lego, betrieb]
created: 2026-09-19
---

## Kontext

Der Vermittler nutzt `lego` als Bibliothek. Zwei Projekte zeigen, was dabei schiefgeht.

## Gelernt

**Ein Konto je Anfrage ist ein Fehler, kein Detail.** `esnet/acme-proxy` erzeugt fuer *jede*
Ausstellung einen frischen ACME-Kontoschluessel und registriert ein neues Konto
([#60](https://github.com/esnet/acme-proxy/issues/60), offen). Zwei Folgen: Let's Encrypt
begrenzt neue Konten (10 je IP und 3 Stunden), und ein **Widerruf** schlaegt fehl, weil er mit
einem Konto signiert wird, das dieses Zertifikat nie bestellt hat — nach RFC 8555 §7.6 nicht
zulaessig. Entstanden ist das als Notloesung gegen `badNonce`-Fehler eines wiederverwendeten
Singleton-Clients ([#11](https://github.com/esnet/acme-proxy/issues/11)); die eine Falle wurde
mit der naechsten geschlossen.

**Die Vorgabe-Zeitgrenze von lego ist zu kurz fuer manche CAs.** `Certificate.Timeout` steht auf
30 Sekunden. Braucht die CA nach dem Abschluss laenger, bricht lego ab — **die CA stellt das
Zertifikat aber trotzdem aus**. Ergebnis: bei jedem Versuch ein weiteres eingesammeltes, nie
abgeholtes Zertifikat ([acme-proxy#56](https://github.com/esnet/acme-proxy/issues/56)).

**Zugangsdaten landen im Log, ohne dass man es merkt.** Bei Cert Warden liefen DNS-Anbieter-Daten
im Klartext durch `journalctl` — aus der Protokollierung der eingebundenen ACME-Bibliothek, nicht
aus eigenem Code ([certwarden#144](https://github.com/gregtwallace/certwarden/issues/144)).

## Wahl

- **Genau ein ACME-Konto je Vermittler und CA**, Schluessel dauerhaft gespeichert und beim Start
  geladen. Ist einer da, wird nie ein neuer erzeugt. Fehlt er, ist das ein lauter Fehler, keine
  stille Neuanlage.
- **Frischer Client je Anfrage — aber mit dem gespeicherten Konto.** Das ist die Aufloesung
  eines scheinbaren Widerspruchs zwischen den beiden Vorbildern. `acme-manager` baut fuer jede
  Anfrage einen neuen lego-Client, ausdruecklich *„to avoid challenge provider pollution"*
  (Commit `45ab83b4`, ein tatsaechlich aufgetretener Fehler): ein wiederverwendeter Client
  traegt die Challenge-Einstellungen der vorherigen Anfrage mit sich. `acme-proxy` macht es
  genauso — erzeugt dabei aber **auch** jedes Mal ein neues Konto und faengt sich damit #60 ein.
  Richtig ist die Kombination: **Client frisch, Konto dauerhaft.** `badNonce` wird dann als das
  behandelt, was es ist — ein erwarteter, wiederholbarer Fehler mit wachsendem Abstand, nicht
  ein Anlass fuer ein neues Konto.
- **Zeitgrenzen werden gesetzt, nicht geerbt:** eine eigene, einstellbare Obergrenze fuer den
  Abschluss, grosszuegiger als 30 Sekunden, und kleiner als die Grenze des umgebenden Aufrufs.
- **Die Protokollierung der Bibliothek wird umgelenkt und gefiltert**, bevor sie irgendwo landet.
  Ein Test prueft, dass keine Anbieter-Zugangsdaten in der Ausgabe auftauchen.
- **Das Zertifikat des Vermittlers selbst wird gespeichert**, nicht bei jedem Start neu geholt.
  step-ca tut Letzteres und kann es nicht abstellen (acme-proxy#40, #62) — bei einer
  ratenbegrenzten CA ist das ein echtes Risiko.

## Konsequenzen

- Kontoschluessel und Zertifikate liegen unter demselben Schutz wie alle Schluessel (0600,
  atomar geschrieben).
- Der Verlust des Kontoschluessels ist ein dokumentierter Wiederherstellungsfall, kein
  Selbstheilungspfad.
