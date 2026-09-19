---
id: ADR-16
type: Decision
title: Eine Sicherung ist erst eine, wenn danach erneuert und ausgeliefert wird
status: erledigt
tags: [betrieb, sicherheit, test]
created: 2026-09-20
---

## Der Anlass

CertMates Sicherungskette ist **viermal** gescheitert, jedes Mal an derselben Stelle:

| Fall | Was passierte |
|---|---|
| [#595](https://github.com/fabriziosalmi/certmate/issues/595) | Eine als „gefahrlos teilbar" ausgewiesene Sicherung enthielt private Schluessel |
| [#655](https://github.com/fabriziosalmi/certmate/issues/655) | Maskierte Sicherungen liessen sich **nicht** zurueckspielen — der juengste Wiederherstellungspunkt war eine Attrappe |
| [#409](https://github.com/fabriziosalmi/certmate/issues/409) | Der Sicherungsumfang liess den Schluessel der eigenen CA aus |
| [#410](https://github.com/fabriziosalmi/certmate/issues/410) | Nach dem Zurueckspielen schlug **jede** Erneuerung dauerhaft fehl |

Der gemeinsame Nenner: geprueft wurde „die Datei ist wieder da", nie „das System arbeitet danach
weiter". Alle vier Sicherungen waren im Sinne ihrer eigenen Pruefung in Ordnung.

## Entschieden

**1. Zwei Arten, die nie verwechselt werden koennen.** Eine vollstaendige Sicherung enthaelt
Schluessel und sagt das im Manifest (`contains_secrets`); nur sie ist `restorable`. Eine
maskierte Sicherung ist fuer die Fehlersuche, traegt `restorable: false` und wird von
`restore-backup` **mit Namen abgelehnt**, bevor irgendetwas auf die Platte geschrieben wird.
Gegen #595 und #655 zugleich: das Werkzeug kann nicht behaupten, teilbar zu sein, und die
Diagnose-Fassung kann nicht als Rettungsanker durchgehen.

**2. Der Umfang steht an einer Stelle, und ein Test geht die Konfiguration ab.**
`backup.PathsFor` ist die einzige Quelle; `TestEveryConfigurationFieldIsClassified` laeuft per
Reflexion durch `config.Config` und faellt bei **jedem** Feld, das niemand eingeordnet hat —
„im Umfang, weil …" oder „kein Pfad". Ein neu hinzugefuegtes Zustandsverzeichnis kann nicht
still aus der Sicherung fallen (#409). Der Preis ist eine Tabelle, die mitgepflegt werden muss;
genau das ist der Zweck.

**3. Das Archiv speichert Bereiche, nicht Wirtspfade.** `account/`, `certificates/`, `state/`,
`server/`, `audit/`. Zurueckgespielt wird ueber die Konfiguration **dieses** Wirts. Damit
gelingt die Wiederherstellung auch auf einer Maschine, die ihren Zustand woanders hat — und
ein Archiv kann nicht bestimmen, wohin dieser Prozess schreibt (Pfade mit `..` werden
abgelehnt, Modi werden beim Zurueckspielen nur enger, nie weiter).

**4. Der Test hoert nicht beim Zurueckspielen auf.** `TestRestoredBrokerRenewsAndDelivers`
zerstoert den gesamten Zustand, spielt zurueck, **oeffnet alles neu von der Platte** und macht
dann die beiden Dinge, fuer die es den Vermittler gibt: eine Erneuerung gegen die CA und eine
Ausgabe an einen Agenten, der sich **vor** dem Ausfall eingeschrieben hat.

Jeder der beiden Schritte faengt eine eigene Art hohler Wiederherstellung:

- Die **Erneuerung** braucht den ACME-Kontoschluessel. Ohne ihn kennt die CA uns nicht mehr und
  keine Erneuerung gelingt je wieder — #410 woertlich.
- Die **Ausgabe** braucht den Schluessel der Agenten-CA und die Registratur. Ohne den Schluessel
  kann sich der Vermittler dem Agenten nicht mehr ausweisen, ohne die Registratur ist der Agent
  ein Fremder. In beiden Faellen ist der Wirt ausgesperrt und kommt nicht von allein zurueck
  ([ADR-7](ADR-7-kein-weg-zurueck-nach-ablauf.md)) — schlimmer als eine fehlgeschlagene
  Erneuerung, weil ein Mensch ran muss.

Belegt ist das nicht durch „der Test ist gruen", sondern durch drei Mutationsproben: faellt der
Kontoschluessel aus dem Umfang, faellt der CA-Schluessel aus dem Umfang, oder tut die Maskierung
nichts — jedes Mal wird der Test rot, und zwar mit der Meldung, die den Fehler benennt.

## Bewusst nicht

- **Kein Verschluesseln im Werkzeug.** Ein Archiv mit Schluesseln ist so schutzwuerdig wie die
  Schluessel; das erledigen age/gpg und die vorhandene Sicherungskette besser als eine
  selbstgebaute Passwortabfrage.
- **Kein Zeitplan, keine Aufbewahrungsregel, kein Hochladen.** `backup` schreibt eine Datei,
  sonst nichts. Ein bestehendes Archiv wird **nie** ueberschrieben — ein fehlgeschlagener Lauf
  darf keinen funktionierenden Wiederherstellungspunkt ersetzen.
- **Keine Wiederherstellung ueber laufenden Zustand ohne `-force`.** Zurueckspielen tauscht
  Kontoschluessel und Agenten-CA; versehentlich getan sperrt es jeden Agenten aus.
