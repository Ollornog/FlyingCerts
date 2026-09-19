---
id: M-7
type: Milestone
title: Geraeteschluessel — Aufnahme ohne Marke, Rueckkehr ohne Eingriff
status: erledigt
tags: [sicherheit, betrieb, aufnahme]
created: 2026-09-20
---

Ein Host soll sich mit einem Schluesselpaar ausweisen, dessen privaten Teil er nie hergibt, und
damit **jederzeit** eine Identitaet bekommen — auch wenn die alte abgelaufen ist.

**Fertig, wenn wahr ist:**

- Der Agent erzeugt sein Schluesselpaar selbst und nennt den Fingerabdruck.
- Der Vermittler autorisiert ueber diesen Fingerabdruck, nicht ueber eine Marke.
- Ein Host mit **abgelaufener** Identitaet kommt **ohne menschlichen Eingriff** zurueck.
- Ein nicht eingetragener Schluessel kommt nicht herein, ein widerrufener Agent auch nicht.
- Die Identitaet benutzt **nicht** denselben Schluessel wie das Geraet.

---

**Erledigt am 20.09.2026.** Entscheidung und der Preis dafuer: [ADR-18](ADR-18-geraeteschluessel.md).

- **[`internal/devicekey`](../internal/devicekey/)** — erzeugen, laden, selbstsigniertes Zertifikat
  je Verbindung. Ein vorhandener Schluessel wird **nie** ueberschrieben.
- **[`internal/keyfp`](../internal/keyfp/)** — Fingerabdruck ueber den oeffentlichen Schluessel
  (SPKI-SHA256, OpenSSH-Format). Ueber den Schluessel, nicht ueber das Zertifikat, sonst waere der
  Wert in der Konfiguration bei jeder Verbindung veraltet.
- **`POST /v1/identity/request`** — dritte Routenart neben offen und mTLS, mit eigener Liste
  (`DevicePaths()`), damit der Abdeckungstest jede Route einer Kategorie zuordnet.
- **`keygen` / `fingerprint`** im Agenten, und `enrol` nimmt jetzt **ohne `-token`** den
  Geraeteschluessel.
- **`run` heilt sich selbst:** fehlende oder abgelaufene Identitaet → neue per Geraeteschluessel.

Der Beweis ist `TestAnExpiredIdentityIsNoObstacle`: eine Identitaet mit einer Sekunde Laufzeit,
danach abgelaufen, mTLS verschlossen — und der Geraeteschluessel oeffnet trotzdem. Dazu der Lauf
von Hand, bei dem ein Host mit abgelaufener Identitaet allein zurueckkam.

Gefunden beim Bauen und Durchspielen:

- **`public_key` erreichte die Registratur nicht.** In Konfiguration, Registratur und Handlern
  vorhanden, nur die eine Zeile in `openBroker` fehlte — alle Einheitstests gruen, Funktion tot.
  Gefunden erst beim Lauf von Hand. Gegenmittel: `TestEveryAgentSpecFieldReachesTheRegistry` geht
  `AgentSpec` per Reflexion ab, jedes Feld muss zugeordnet und geprueft sein (Mutationsprobe
  belegt, dass der Test greift).
- **`tls.Certificate.Leaf` war die Vorlage statt des geparsten Zertifikats** — eine Vorlage hat
  kein `PublicKey`-Feld, und Gos TLS-Stack liest `Leaf`, wenn es gesetzt ist.
- **Der alte TLS-Test schrieb den alten Vertrag fest.** Ersetzt durch einen, der den neuen nennt,
  **plus** `verify_test.go` mit fuenf Faellen, die abgelehnt werden muessen — die Garantie ist von
  der Bibliothek in unseren Code gewandert, also gehoert sie geprueft.
- **Der Agent stellte zweimal hintereinander aus**, wenn eine frisch geholte Identitaet wegen sehr
  kurzer Laufzeit sofort wieder erneuerungsfaellig war.
