---
id: M-6
type: Milestone
title: Einstellbare Identitaets-Laufzeit
status: erledigt
tags: [betrieb, sicherheit]
created: 2026-09-20
---

Hosts sind verschieden. Eine Maschine, die jede Nacht aus einem Abbild neu entsteht, braucht
keine Identitaet, die dreissig Tage haelt; ein Geraet, zu dem jemand hinfahren muss, soll sich
nicht aussperren koennen.

**Fertig, wenn wahr ist:**

- Die Laufzeit einer Agenten-Identitaet ist einstellbar — vermittlerweit **und je Agent**.
- Sie ist in der Einheit schreibbar, in der man darueber spricht (Tage), nicht nur in Stunden.
- **`unlimited`** ist moeglich, und was das wirklich bedeutet, steht dran statt verschwiegen zu
  werden.
- Eine Identitaet ueberlebt nie die CA, die sie ausgestellt hat.
- `agents` und `check` machen sichtbar, was eingestellt ist — und eine unbegrenzte Identitaet
  laesst `check` nicht bei jedem Lauf fehlschlagen.

---

**Erledigt am 20.09.2026.** Entscheidung und Abwaegung: [ADR-17](ADR-17-einstellbare-laufzeit.md).

- **[`internal/lifetime`](../internal/lifetime/)** — ein Typ fuer alle vier Pakete, die ihn
  brauchen. Versteht `1d`, `30d`, `1d12h`, `12h` und `unlimited`; haelt **unbelegt**, **Dauer**
  und **unbegrenzt** als drei verschiedene Zustaende auseinander. Ein blosses `30` wird
  abgelehnt, weil es fuer den Schreibenden Tage und fuer den Parser Nanosekunden heisst.
- **Je Agent** (`agents[].identity_lifetime`) mit Rueckfall auf `broker.identity_lifetime` und
  von dort auf den Vorgabewert. Der Rueckfall wird bei jeder Ausstellung aufgeloest, nicht beim
  Laden — ein geaenderter Vermittler-Wert erreicht so jeden Agenten, der nichts eigenes gesetzt
  hat, bei dessen naechster Erneuerung.
- **`unlimited` heisst: bis die CA ablaeuft.** Ein Zertifikat ohne Ablauf gibt es nicht; die
  Anzeige sagt deshalb `until CA (2036-09-16)` und nicht „unbegrenzt".
- **Keine Identitaet ueberlebt ihre CA.** Geprueft wird gegen das **tatsaechliche** Ende der CA,
  nicht gegen ihre nominelle Laufzeit — eine acht Jahre alte CA hat weniger uebrig, als sie
  ausgestellt wurde. Eine zu lange Laufzeit wird **abgelehnt**, nicht still gekuerzt; nur
  `unlimited` laeuft absichtlich genau bis dorthin.
- **`SignAgent` gibt das Ablaufdatum zurueck**, statt es den Aufrufer nachrechnen zu lassen. Die
  Registratur zeichnet damit die Zeit **aus dem Zertifikat** auf. Vorher rechneten zwei Stellen
  dasselbe Datum aus denselben Eingaben aus — und waeren bei `unlimited` um ein Jahrzehnt
  auseinandergelaufen.

Nebenbefunde beim Durchspielen von Hand:

- **Derselbe Flag-Fehler steckte auch im Agenten** (`enrol -token …` gab die Nutzung aus). Jetzt
  in beiden Programmen behoben **und durch einen Test gesichert**, der den echten Einstiegspunkt
  aufruft — belegt durch Mutationsprobe.
- **`SignServer` deckelte nicht gegen das CA-Ende** (dieselbe Wurzel wie oben, andere Funktion).
- **Das zurueckgegebene Ablaufdatum hatte Nanosekunden**, das Zertifikat speichert Sekunden. Der
  aufgezeichnete Wert war damit nie exakt der des Zertifikats — unsichtbar, und trotzdem eine
  Angabe, die etwas anderes behauptet, als sie ist.
