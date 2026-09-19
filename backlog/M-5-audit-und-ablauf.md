---
id: M-5
type: Milestone
title: Aufzeichnung und Ablaufverfolgung
status: erledigt
tags: [audit, betrieb]
created: 2026-09-19
---

Der Grund, warum der Vermittler ueberhaupt in der Mitte steht: er weiss, wer was wann bekommen
hat — und was demnaechst ausgeht.

**Fertig, wenn wahr ist:**

- Jede Anforderung wird mit Agent, Gegenstand, Zeit und Ergebnis aufgezeichnet; die Identitaet
  stammt aus dem Client-Zertifikat, nicht aus einer Angabe des Aufrufers.
- Der Vermittler kann ausgeben, welcher Agent wann zuletzt geholt hat und wann sein Zertifikat
  ablaeuft.
- Ein Agent, der laenger nicht geholt hat, faellt auf — bevor sein Zertifikat ablaeuft.

---

**Erledigt am 20.09.2026.**

- **Jede Anforderung wird aufgezeichnet.** `internal/brokerapi` schreibt Agent, Gegenstand, Zeit
  und Ergebnis ins Protokoll; der Agentname stammt aus `VerifiedChains` des Client-Zertifikats
  und **nie** aus einer Angabe des Aufrufers — der Weg ueber einen Kopfzeilen-Wert existiert
  gar nicht erst ([ADR-2](ADR-2-mtls-statt-api-keys.md)).
- **Der Vermittler kann Auskunft geben.** `agents` zeigt je Agent Modus, letzten Kontakt,
  Restlaufzeit der Identitaet und Anzahl der Zertifikate. Der Zustand haelt seit dieser Runde
  auch `identity_expires`, gesetzt beim Einschreiben **und** bei jeder Identitaetserneuerung.
- **Ein Agent, der schweigt, faellt auf, bevor sein Zertifikat ablaeuft.**
  `registry.Review` unterscheidet vier Lagen — nie eingeschrieben, verstummt, Aussperrung
  droht, ausgesperrt — und ordnet sie nach Dringlichkeit. `check` gibt sie aus und endet
  **ungleich null**, wenn etwas anliegt, ist also direkt als Ueberwachung brauchbar. Wer absichtlich
  widerrufen wurde, taucht nicht als Problem auf.
- **`serve`** faehrt den Endpunkt samt stuendlichem Aufraeumen (verbrauchte Marken,
  Ratenzaehler) und geordnetem Herunterfahren; sein eigenes TLS-Zertifikat stellt er aus der
  Agenten-CA aus, damit ein Agent es mit dem pruefen kann, was er bei der Aufnahme bekam.
- **`revoke` / `restore`** sperren einen Agenten sofort aus bzw. heben das auf. Wirksam bei der
  naechsten Anfrage, weil jede Anfrage die Registratur liest.
- **Sicherung** (T-3, [ADR-16](ADR-16-sicherung.md)): `backup`, `backup-info`, `restore-backup` —
  mit dem Test, der nach dem Zurueckspielen erneuert und ausliefert.

Gefunden und behoben beim Durchspielen von Hand: Gos `flag` bricht am ersten Nicht-Flag-Argument
ab, wodurch `token -agent gateway` als „Befehl plus zwei Streuargumente" ankam und die Nutzung
ausgab statt eine Marke. Befehlsflags werden seitdem in einem eigenen `FlagSet` **nach** dem
Befehlsnamen gelesen — also so, wie ein Mensch es tippt.
