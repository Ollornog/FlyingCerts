---
id: ADR-6
type: Decision
title: Bootstrap-Token — Parameter und Bindungen, gelernt an step-ca
status: erledigt
tags: [auth, sicherheit, bootstrap]
created: 2026-09-19
---

## Kontext

[ADR-2](ADR-2-mtls-statt-api-keys.md) entscheidet *dass* ein einmaliges Bootstrap-Token die
Aufnahme traegt. Diese Entscheidung legt fest, *wie* — anhand der Werte, die smallstep in
step-ca ueber Jahre eingestellt hat, und anhand der Luecken, die sie dabei gefunden haben.

## Wahl

**Lebensdauer: 5 Minuten** (einstellbar). step-ca nutzt genau diesen Wert
(`tokenLifetime = 5 * time.Minute`). Lang genug fuer eine Aufnahme, kurz genug, dass ein
abgefangenes Token selten noch brauchbar ist.

**Einmaligkeit ueber eine Token-Kennung (`jti`) in einem Speicher, der Neustarts ueberlebt.**
step-ca faellt ohne konfiguriertes Datenbank-Backend still auf eine reine `sync.Map` zurueck
(`db/simple.go`) — der Wiedereinloese-Schutz ist dann **nur im Arbeitsspeicher**: weg nach
einem Neustart und nicht geteilt, wenn mehrere Instanzen laufen. Wir bauen den Speicher von
Anfang an dauerhaft; einen „geht auch ohne"-Modus gibt es nicht.

**Uhrzeit-Toleranz: 1 Minute** in beide Richtungen, wie step-ca (`ValidateWithLeeway`). Der
Fehler muss ausdruecklich sagen, dass die Uhren auseinanderlaufen — step-ca hat genau hier eine
seit Jahren offene Schwaeche (Issues certificates#339, #2055): nur ein harter Ein/Aus-Schalter,
keine feine Toleranz, und die Fehlermeldung nennt die Ursache nicht.

**Das Token bindet an: Agentenname, erlaubte Namen, den Fingerabdruck des Vermittler-Zertifikats
und den Fingerabdruck des konkreten CSR.** Der letzte Punkt ist die Lehre: step-cas
urspruengliches Modell band das Token nur an Namen und CA, nicht an die Anfrage — ein
abgefangenes Token liess sich mit einem *anderen*, aber namenskonformen CSR einloesen. Erst
certificates#1637 / PR #1660 schloss das ueber einen `cnf`-Anspruch mit CSR-Fingerabdruck
(RFC 7800). Wir haben das von Anfang an, nicht als Nachruestung.

**Namenspruefung: exakte Mengengleichheit, keine Teilmenge.** step-ca vergleicht Token-Namen und
CSR-Namen mit `reflect.DeepEqual` (`sign_options.go`). Ein CSR mit einem zusaetzlichen Namen
wird abgelehnt — nicht beschnitten, nicht durchgewunken.

## Konsequenzen

- Der Vermittler braucht eine dauerhafte Ablage fuer verbrauchte Token-Kennungen, samt
  Aufraeumen abgelaufener Eintraege (step-ca hat dafuer bis heute keine Loesung:
  certificates#473).
- Die Einmaligkeit muss auch bei zwei **gleichzeitigen** Einloesungen halten — also ein
  atomares „anlegen, wenn nicht vorhanden", kein Lesen-dann-Schreiben.
- Uhrzeitfehler brauchen eine eigene, erkennbare Fehlermeldung.
