---
id: ADR-3
type: Decision
title: Zwei Ausliefermodi, `issue` ist der empfohlene
status: erledigt
tags: [architektur, sicherheit]
created: 2026-09-19
---

## Kontext

Es gibt zwei ehrliche Arten, einen internen Host mit einem Zertifikat zu versorgen: ihm ein
eigenes ausstellen, oder ihm ein geteiltes samt Schluessel geben. Sie sind nicht gleich gut.

## Optionen

- **`issue`** — der Agent erzeugt seinen Schluessel lokal und schickt nur einen CSR. Es reist
  nie ein privater Schluessel. Weil je Agent ausgestellt wird, hat „wann laeuft dieser Host ab"
  eine echte Antwort.
- **`share`** — der Vermittler gibt ein Zertifikat samt privatem Schluessel an alle dafuer
  berechtigten Agenten. Einfacher und manchmal die einzige Moeglichkeit (etwa fuer ein
  Platzhalter-Zertifikat, das mehrere Hosts unter demselben Namen bedienen), aber der Schluessel
  reist, und alle Halter teilen ein Schicksal.

## Wahl

Beide, einstellbar je Agent oder Gruppe — mit `issue` als Vorgabe und ausdruecklicher
Empfehlung. `share` wird in der Doku als der schwaechere Modus benannt, nicht als gleichwertige
Alternative.

## Konsequenzen

- Im Modus `issue` braucht es eine **serverseitige Namenspruefung**: ein Agent darf kein
  Zertifikat fuer einen Namen bekommen, der ihm nicht zugeordnet ist (M-3).
- Im Modus `share` ist Ablauf eine Eigenschaft des Zertifikats, nicht des Hosts; die
  Ablaufverfolgung je Agent kann dort nur den letzten Abholzeitpunkt zeigen. Das muss die
  Ausgabe kenntlich machen, statt eine Genauigkeit vorzutaeuschen, die es nicht gibt.
- Zwei Modi heissen zwei Testpfade. Beide gehoeren in die Suite, sonst verrottet der seltenere.
