---
id: M-4
type: Milestone
title: Agent — anfordern, ablegen, neu laden
status: erledigt
tags: [client]
created: 2026-09-19
---

Das Gegenstueck auf dem internen Host. Ein einzelnes Binary, das per Timer laeuft.

**Fertig, wenn wahr ist:**

- Bootstrap mit Token, danach Anforderung ausschliesslich per mTLS.
- Zertifikat wird atomar geschrieben, mit einstellbarem Eigentuemer und Rechten.
- Nach einer Erneuerung laeuft ein Hook — und der Agent **prueft, ob er gewirkt hat**
  (siehe ADR-5), statt sich auf den Rueckgabewert zu verlassen.
- Laeuft nichts Neues an, passiert nichts: kein Schreiben, kein Hook, kein Rauschen.

**Erledigt (2026-09-20).** Der Agent enrolliert einmal, weist sich danach per mTLS aus, holt
seine Zertifikate und legt sie ab.

Das Herzstueck ist `internal/deploy` und damit ADR-5: nach dem Neuladen wird per TLS geprueft,
**was der Dienst tatsaechlich ausliefert**, verglichen ueber den Fingerabdruck. Ein Test stellt
genau den Caddy-Fall nach — Reload-Befehl gibt 0 zurueck, der Dienst liefert weiter das alte
Zertifikat — und er faengt ihn. Das ist die Fehlerklasse, die im September 2026 vier Wochen
unbemerkt blieb.

Weitere Entscheidungen mit eigenem Test:

- **Ohne `verify_address` wird gewarnt, nicht Erfolg gemeldet.** Ein Werkzeug, das „deployed"
  sagt, ohne nachgesehen zu haben, erzeugt genau das falsche Vertrauen. Die Warnung kommt bei
  jedem Lauf, nicht einmalig.
- **Nichts Neues heisst nichts tun** — kein Schreiben, kein Reload. Sonst wird aus einem
  Fuenf-Minuten-Timer ein Dienstneustart alle fuenf Minuten.
- **Der Reload-Befehl ist argv, keine Shell-Zeile.** Das nimmt die Injektionsflaeche ganz weg
  und die Quoting-Fehler gleich mit (step-ca cli#1538; acme-manager trennt an Leerzeichen).
  Zwei Tests: ein Argument mit Leerzeichen bleibt eines, und Shell-Syntax wird nicht ausgefuehrt.
- **Schluessel zuerst, Kette danach.** Bricht es dazwischen ab, ist ein alter Schluessel harmlos —
  eine neue Kette ohne Schluessel sieht vollstaendig aus und scheitert am Handshake.
- **Eine abgelaufene Identitaet bekommt eine eigene Fehlermeldung**, die sagt, was zu tun ist
  (ADR-7). Als Verbindungsfehler getarnt wuerde jemand das Netz durchsuchen.

`agentca.SignServer` kam dabei dazu: Der Vermittler braucht ein TLS-Zertifikat, das Agenten mit
dem verifizieren koennen, was ihnen die Aufnahme gegeben hat. Getrennt von `SignAgent`, weil die
beiden Gegenteile sind — ein Ausweis darf nur ausweisen, ein Server-Zertifikat nur ausliefern.
