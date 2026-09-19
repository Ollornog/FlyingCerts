---
id: T-1
type: Task
title: "Gesundheitspruefung eines Zertifikats prueft das PAAR, nicht nur das Zertifikat"
status: erledigt
milestone: M-1
tags: [sicherheit, test]
created: 2026-09-19
---

CertMate meldete Zertifikate als gesund, weil nur `cert.pem` geprueft wurde — der fehlende
private Schluessel fiel nie auf ([#608](https://github.com/fabriziosalmi/certmate/issues/608)).
Reproduzierbar nach dem Zurueckspielen einer Sicherung; der Erneuerungsplaner ruehrte das kaputte
Zertifikat 44 Tage lang nicht an. Derselbe Fehler kam spaeter zurueck
([#830](https://github.com/fabriziosalmi/certmate/issues/830)).

**Zu tun:** Ein Zertifikat gilt nur als vollstaendig, wenn Zertifikat **und** passender
Schluessel vorliegen und die oeffentlichen Schluessel uebereinstimmen. Diese Pruefung ist die
einzige Quelle fuer „gesund" — in der Anzeige, im Erneuerungsplaner und in der Ausgabe an Agenten.

Die Pruefung selbst wird **nicht von Hand gebaut**: `tls.X509KeyPair` vergleicht die oeffentlichen
Schluessel bereits intern und meldet `tls: private key does not match public key`
(siehe [ADR-13](ADR-13-go-handwerk.md)).

**Fertig, wenn:** Ein Test legt ein Zertifikat ohne Schluessel ab und weist nach, dass es als
unvollstaendig gilt und zur Erneuerung ansteht statt als gesund durchzugehen.

**Erledigt (2026-09-19):** `certstore.Save` speichert nur, was `certinfo.LoadPair` als gültiges
Paar annimmt; `certstore.Load` prüft beim Lesen erneut. Ein Zertifikat ohne Schlüssel meldet
ausdrücklich **nicht** „nicht gespeichert" — das würde einen Aufrufer dazu bringen, ein zweites
zu holen, statt das halbfertige zu reparieren. Tests: `TestSaveRejectsMismatchedPair`,
`TestChainWithoutKeyIsNotReportedAsMissing`, `TestLoadPairRejectsMismatch`.
