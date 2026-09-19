---
id: T-3
type: Task
title: "Der Sicherungs-Test spielt zurueck UND faehrt danach eine Erneuerung"
status: erledigt
milestone: M-5
tags: [betrieb, test]
created: 2026-09-19
---

CertMates Sicherungskette hat dieselbe Schwaeche viermal gezeigt: Sicherungen, die als
„gefahrlos teilbar" ausgewiesen waren, enthielten private Schluessel
([#595](https://github.com/fabriziosalmi/certmate/issues/595)); maskierte Sicherungen liessen
sich **nicht** zurueckspielen, der juengste Wiederherstellungspunkt war also eine Attrappe
([#655](https://github.com/fabriziosalmi/certmate/issues/655)); der Sicherungsumfang liess
Schluessel der eigenen CA aus ([#409](https://github.com/fabriziosalmi/certmate/issues/409));
und nach dem Zurueckspielen schlug **jede** Erneuerung dauerhaft fehl
([#410](https://github.com/fabriziosalmi/certmate/issues/410)).

Der gemeinsame Nenner: geprueft wurde „die Datei ist wieder da", nie „das System arbeitet danach
weiter".

*(Gehoert zum Betrieb, nicht zum Grundgeruest — deshalb an M-5 statt M-1. Eine Sicherung gibt es
erst, wenn es auch Zustand gibt, der ueber Zertifikate hinausgeht.)*

**Zu tun:** Der Test sichert, zerstoert den Zustand, spielt zurueck **und fuehrt anschliessend
eine vollstaendige Erneuerung samt Ausgabe an einen Agenten durch**. Was als maskiert
ausgewiesen wird, wird im Test auf Schluesselmaterial durchsucht.

**Fertig, wenn:** Der beschriebene Ablauf als Test laeuft — und beim zweiten Lauf ebenso gruen ist.

---

**Erledigt am 20.09.2026.** Paket `internal/backup` (Archiv mit Manifest, zwei Arten, Bereiche
statt Wirtspfade), Befehle `backup` / `backup-info` / `restore-backup`, Entscheidung als
[ADR-16](ADR-16-sicherung.md).

Der geforderte Ablauf laeuft als `TestRestoredBrokerRenewsAndDelivers`: sichern, gesamten Zustand
loeschen, zurueckspielen, **alles neu von der Platte oeffnen**, gegen Pebble erneuern und an den
vor dem Ausfall eingeschriebenen Agenten ausliefern — geprueft wird die Seriennummer, die beim
Agenten ankommt. Was als maskiert ausgewiesen wird, durchsucht
`TestRedactedArchiveContainsNoKeyMaterial` im entpackten Archiv auf Schluesselmaterial.

Dass die Tests etwas fangen, ist mit drei Mutationsproben belegt (Kontoschluessel aus dem Umfang,
CA-Schluessel aus dem Umfang, Maskierung wirkungslos) — jede wird rot, jede mit der Meldung, die
den Fehler benennt. Zweiter Lauf ebenfalls gruen.
