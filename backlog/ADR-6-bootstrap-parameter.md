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

**Das Token bindet an: Agentenname, erlaubte Namen und den Fingerabdruck der Ausweis-Wurzel.**

**Nicht an den CSR — und das korrigiert die erste Fassung dieser Entscheidung.** Hier stand
zunaechst, wir uebernaehmen step-cas CSR-Bindung (`cnf`-Anspruch, RFC 7800, nachgeruestet in
certificates#1637 / PR #1660) von Anfang an. Beim Bau zeigte sich: **in unserem Ablauf geht das
nicht.** Bei step-ca erzeugt *dieselbe* Person CSR und Token (`step ca token --csr …`). Bei uns
stellt ein Mensch das Token aus und gibt es einem Host, der seinen Schluessel — und damit den
CSR — **erst danach** erzeugt. Zum Zeitpunkt der Ausstellung existiert nichts, woran zu binden
waere.

Erzwingen liesse es sich (Agent erzeugt CSR, meldet den Fingerabdruck, bekommt dann ein Token),
aber das macht aus einem Handgriff zwei Runden und bringt wenig: Wer das Token abfaengt, faengt
es auf dem Weg zum Host ab — also **bevor** der CSR existiert — und erzeugt sich dann einfach
einen eigenen. Die CSR-Bindung schuetzt gegen das Ersetzen eines *bereits vorhandenen* CSR, nicht
gegen ein abgefangenes Token.

Was stattdessen traegt: Das Token ist **kurzlebig**, **einmalig**, an **einen** Namen gebunden
und an **diese** Ausweis-Wurzel — es laesst sich also weder wiederverwenden noch gegen eine
andere Installation einloesen. Der Transport zum Host bleibt der schwache Punkt; den nennt die
Doku beim Namen, statt ihn mit einer Bindung zu kaschieren, die ihn nicht abdeckt.

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
