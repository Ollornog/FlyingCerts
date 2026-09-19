---
id: ADR-5
type: Decision
title: Nach dem Neuladen wird die Wirkung geprueft, nicht der Rueckgabewert
status: erledigt
tags: [client, betrieb, sicherheit]
created: 2026-09-19
---

## Kontext

Der Agent legt ein erneuertes Zertifikat ab und laedt den Dienst neu. Der uebliche Bau ist:
Hook ausfuehren, Rueckgabewert pruefen, fertig. Das reicht nicht.

Ein bekanntes Beispiel: `caddy reload` vergleicht die **Konfiguration**. Aendert sich nur eine
Zertifikatsdatei auf der Platte, bleibt die Konfiguration gleich — der Dienst meldet
`config is unchanged`, tut nichts und endet mit Rueckgabewert 0. Das alte Zertifikat bleibt im
Speicher, bis der Prozess neu startet
([caddyserver/caddy#6948](https://github.com/caddyserver/caddy/issues/6948)). Der Agent haelt
das fuer Erfolg und schweigt, und zwar so lange, bis das alte Zertifikat wirklich ablaeuft —
Wochen spaeter, ohne Zusammenhang zum ausloesenden Ereignis.

Das ist kein Sonderfall dieses einen Dienstes, sondern die Regel: „Befehl gab 0 zurueck" heisst
nicht „der Dienst benutzt jetzt das neue Zertifikat".

## Wahl

Der Agent prueft nach dem Hook **nach**, was tatsaechlich ausgeliefert wird: TLS-Verbindung zum
konfigurierten Endpunkt, Vergleich des vorgelegten Zertifikats mit dem gerade geschriebenen
(Fingerabdruck, nicht nur Ablaufdatum). Erst dann gilt die Erneuerung als erfolgt.

## Konsequenzen

- Der Agent braucht je Zertifikat einen pruefbaren Endpunkt (Adresse + Servername). Fehlt er,
  laeuft er im Warnmodus: er meldet, dass er die Wirkung nicht bestaetigen konnte, statt Erfolg
  zu behaupten.
- Schlaegt die Pruefung fehl, ist das ein Fehler mit von Null verschiedenem Rueckgabewert — und
  der Vermittler erfaehrt es bei der naechsten Anforderung.
- Das faengt zugleich den zweiten haeufigen Fehler: falsche Rechte oder Eigentuemer an der
  Schluesseldatei, sodass der Dienst sie nicht lesen kann und still beim alten bleibt.
