---
id: ADR-17
type: Decision
title: Identitaets-Laufzeit je Agent, inklusive unlimited — mit offener Rechnung
status: erledigt
tags: [betrieb, sicherheit, konfiguration]
created: 2026-09-20
---

## Die Frage

Wie lange gilt die Identitaet eines Agenten? Bisher: dreissig Tage, vermittlerweit, fertig.
Das passt nicht auf jede Maschine — und die Vorlage aus der eigenen Flotte (NetBird-Setup-Keys:
ein Tag, dreissig Tage, unbegrenzt) zeigt, was gemeint ist.

## Entschieden

**Je Agent einstellbar, mit Rueckfallkette.** `agents[].identity_lifetime` schlaegt
`broker.identity_lifetime` schlaegt Vorgabewert (30d). Aufgeloest wird bei jeder Ausstellung,
nicht beim Laden: so erreicht ein geaenderter Vermittler-Wert jeden Agenten, der nichts eigenes
gesetzt hat, ohne dass jemand die Hosts anfasst.

**In Tagen schreibbar.** Gos Dauer-Schreibweise hoert bei Stunden auf; `720h` ist nicht falsch,
nur unlesbar — und ein Konfigurationswert, den niemand auf einen Blick pruefen kann, ist einer,
der irgendwann falsch dasteht. Also `30d`, `1d12h`, und weiterhin alles, was Go kennt.

**Drei Zustaende, die nie zusammenfallen:** unbelegt (nimm den Rueckfall), eine Dauer, und
`unlimited`. Deshalb ein eigener Typ und keine `time.Duration`: bei einer Zahl waere Null
zugleich „nicht gesetzt" und „sofort abgelaufen", und `unlimited` waere eine grosse Zahl, die man
irgendwann fuer eine Dauer haelt. Ein blosses `30` wird **abgelehnt** — es heisst fuer den
Schreibenden Tage und fuer den Parser Nanosekunden, und keine der beiden Lesarten ist es wert,
geraten zu werden.

## `unlimited` — was es kostet, ausgeschrieben

Der Projektzweck war unter anderem, **langlebige gemeinsame Geheimnisse loszuwerden**
([ADR-2](ADR-2-mtls-statt-api-keys.md)): kein API-Schluessel, der ein Jahr in einer Datei liegt,
sondern eine Identitaet, die sich von selbst zurueckzieht. `unlimited` gibt genau diese
Eigenschaft wieder her. Das ist keine Kleinigkeit, und es wird hier nicht weggeschrieben:

- **Nur ein Widerruf nimmt die Identitaet zurueck.** Ohne Ablauf gibt es keinen Zeitpunkt, an
  dem ein vergessener Host von selbst aufhoert, Zutritt zu haben. Ein Rechner, der ausgemustert
  und nie widerrufen wurde, kann Jahre spaeter noch Zertifikate abholen.
- **Ein kopierter Schluessel bleibt gueltig.** Bei dreissig Tagen laeuft eine Kopie von selbst
  aus, und die Erneuerung ist eine regelmaessige Gelegenheit, dass etwas auffaellt. Unbegrenzt
  faellt diese Gelegenheit weg.
- **Es gibt kein Zertifikat ohne Ablauf.** `unlimited` heisst in Wahrheit „bis die CA ablaeuft"
  — bei uns bis zu zehn Jahre. Genau so wird es auch angezeigt (`until CA (2036-09-16)`), statt
  eine Unendlichkeit zu behaupten, die das Format nicht kennt.

**Trotzdem gebaut**, weil der Gegenfall real ist: ein Geraet, zu dem jemand hinfahren muss, sperrt
sich bei einer abgelaufenen Identitaet endgueltig aus
([ADR-7](ADR-7-kein-weg-zurueck-nach-ablauf.md)) — und ein Ausfall, der einen Menschen mit einem
Auto braucht, ist teurer als ein Zertifikat, das laenger gilt. Die Entscheidung gehoert dem
Betreiber; die Aufgabe des Werkzeugs ist, sie **sichtbar** zu machen.

Deshalb:

- `agents` zeigt die eingestellte Laufzeit in einer eigenen Spalte, damit `unlimited` nicht erst
  auffaellt, wenn irgendwo „3650 Tage" steht.
- `check` meldet jede unbegrenzte Identitaet mit dem Satz, der den einzigen Hebel nennt: *only a
  revocation can take this identity back*.
- **Und laesst deswegen den Lauf nicht fehlschlagen.** Ein Dauerzustand, der jedes Mal rot ist,
  bringt Leute dazu, die Ausgabe nicht mehr zu lesen — und dann geht die echte Warnung mit unter.
  `Concern.NeedsAction()` trennt „hier muss jemand ran" von „das sollte man wissen"; nur das
  erste bestimmt den Rueckgabewert.

## Keine Identitaet ueberlebt ihre CA

Geprueft wird gegen das **tatsaechliche** `NotAfter` der CA, nicht gegen die Laufzeit, mit der
sie erzeugt wurde. Eine CA, die seit acht Jahren laeuft, hat zwei Jahre uebrig — die alte
Pruefung („ist die gewuenschte Dauer kleiner als zehn Jahre?") haette dort eine Identitaet
ausgestellt, die ihren Aussteller ueberlebt. Solche Zertifikate hoeren ohne erkennbaren Grund
auf zu funktionieren, und in keinem Protokoll steht, warum.

Eine zu lange Laufzeit wird **abgelehnt** statt gekuerzt: sonst sagt die Konfiguration das eine
und das Zertifikat das andere. `unlimited` ist die einzige Ausnahme — dort *ist* das CA-Ende die
Absicht.

## Bewusst nicht

- **Keine Obergrenze ausser der CA.** Wer `unlimited` schreibt, meint es; eine erfundene
  Hoechstdauer waere Bevormundung mit Extraschritten.
- **Kein automatisches Verkuerzen.** Siehe oben: still geaenderte Werte sind schlimmer als
  abgelehnte.
- **Keine Laufzeit-Einstellung fuer die Nutz-Zertifikate.** Die bestimmt die CA, nicht wir.
