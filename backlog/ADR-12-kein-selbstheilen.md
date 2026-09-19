---
id: ADR-12
type: Decision
title: Bei erkannter Unstimmigkeit wird gemeldet, nicht selbst geheilt
status: erledigt
tags: [betrieb, acme, sicherheit]
created: 2026-09-19
---

## Kontext

Wenn der gespeicherte Zustand und das, was tatsaechlich auf der Platte liegt, auseinanderlaufen
— was soll das Werkzeug tun? Der hilfsbereite Reflex ist: neu ausstellen, Problem weg.

`acme-manager` hat genau diese Frage durchdacht und sich **dagegen** entschieden (PR #36). Die
Begruendung im Projekt selbst: *„Recreating the certificate on a fingerprint mismatch would turn
any server-side inconsistency … into an unbounded issuance loop against the CA."* Aus einer
stillen Unstimmigkeit wuerde also eine Dauerschleife gegen die CA — mit Ratenbegrenzung als
Folge, und zwar fuer alle Zertifikate, nicht nur das kaputte. Sie melden stattdessen eine
Kennzahl und lassen den Menschen entscheiden.

Dasselbe Muster von der anderen Seite: Cert Warden erneuert **nicht**, wenn ein Zertifikat
ablief, waehrend der Dienst aus war ([#125](https://github.com/gregtwallace/certwarden/issues/125)),
ausdruecklich damit tote Zertifikate nicht dauerhaft gegen die CA gehaemmert werden. Der Preis
ist dort allerdings, dass gar nichts passiert, bis jemand von Hand klickt.

## Wahl

- **Unstimmigkeiten werden erkannt und laut gemeldet** (Kennzahl, Protokoll, sichtbar in der
  Ausgabe des Vermittlers) — aber nicht selbsttaetig durch Neuausstellung „repariert".
- **Jede Neuausstellung hat eine Obergrenze je Zeitraum und Gegenstand.** Auch ein
  wohlmeinender Pfad darf nicht unbegrenzt bestellen koennen.
- **Was ohne CA behebbar ist, wird behoben:** ein Agent, der eine veraltete Datei hat, bekommt
  das vorhandene Zertifikat erneut ausgeliefert. Das kostet die CA nichts und ist kein
  Selbstheilen im obigen Sinn.

## Konsequenzen

- Es braucht einen sichtbaren Zustand „unstimmig, Eingriff noetig" — sonst wird aus „wir heilen
  nicht" ein stilles Liegenbleiben wie bei certwarden#125.
- Der Unterschied zwischen „nur erneut ausliefern" (frei) und „neu bestellen" (teuer, begrenzt)
  muss im Code eine sichtbare Grenze sein, keine Feinheit im Kontrollfluss.
