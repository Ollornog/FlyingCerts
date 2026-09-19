---
id: ADR-13
type: Decision
title: Handwerk — lego v5, atomares Schreiben, Zertifikatstausch im Betrieb
status: erledigt
tags: [go, handwerk, sicherheit]
created: 2026-09-19
---

## lego v5, nicht v4

lego ist am **11.05.2026 auf v5 gesprungen** (aktuell v5.5.1). Die Bibliotheks-Schnittstelle hat
sich dabei geaendert: **`context.Context` in allen Aufrufen**, `crypto.Signer` statt
`crypto.PrivateKey` im `registration.User`-Vertrag, `slog` als Protokollierung, PKCS#8.

**Folge fuer uns:** Praktisch jedes Beispiel im Netz — und jedes aus dem Gedaechtnis — zeigt v4
und uebersetzt gegen v5 **nicht**. Es wird ausschliesslich gegen die gepinnte Fassung geprueft
(`pkg.go.dev/github.com/go-acme/lego/v5/...@v5.5.1`), nie gegen Beispiele.

Angenehme Folge: Zeitgrenzen und Abbruch sind ab v5 Bordmittel ueber den Kontext. Die eigene
Obergrenze aus [ADR-10](ADR-10-acme-konto-und-lego.md) wird damit gesetzt, nicht um lego
herumgebaut.

**lego drosselt nichts von selbst.** Ein Vorschlag dafuer liegt seit 2019
([#976](https://github.com/go-acme/lego/issues/976)), und `Retry-After` wurde beim Abfragen des
Auftrags ignoriert ([#1601](https://github.com/go-acme/lego/issues/1601)). Ob v5 daran etwas
geaendert hat, ist offen — wir bauen Abstand und Streuung selbst und pruefen den Stand beim Pinnen.

## Dateien schreiben

**Der Modus gehoert in `os.OpenFile`, niemals in ein nachtraegliches `Chmod`.** Die umask kann
Rechte nur *entfernen*, nie hinzufuegen — `os.OpenFile(pfad, …, 0600)` ist also immer hoechstens
0600. Gefaehrlich ist allein das Muster `os.Create()` (fordert 0666 an) gefolgt von `Chmod`:
dazwischen liegt die Datei mit `0666 & ~umask` lesbar herum. Das ist die Falle, nicht die umask.

**Atomar heisst: in dasselbe Verzeichnis schreiben, `Sync()`, dann `os.Rename`.** Ein anderes
Verzeichnis oder ein anderer Einhaengepunkt macht das Umbenennen nicht-atomar. Ein
Verzeichnis-`Sync()` danach erhoeht die Absturzsicherheit; das ist POSIX-Praxis, keine
Go-Vorgabe. Entweder selbst so bauen oder `google/renameio` nehmen, das genau dieses Muster
implementiert.

## Zusammengehoerigkeit nicht selbst pruefen

`tls.X509KeyPair` vergleicht die oeffentlichen Schluessel **bereits intern** und meldet
`tls: private key does not match public key`. Wir bauen keine eigene Vergleichsroutine, sondern
nutzen diesen Aufruf als Pruefung — kuerzer und mit weniger Gelegenheit, es falsch zu machen.

## Zertifikat im Betrieb tauschen

Das Zertifikat wird **nicht** in `tls.Config.Certificates` gelegt — was dort einmal liegt, bleibt
bis zum Prozessende. Stattdessen `GetCertificate` (Server) und `GetClientCertificate` (Agent) als
Rueckruf, dahinter ein `atomic.Value`: bei jedem Handshake gelesen, beim Erneuern einmal
geschrieben, kein Sperren im heissen Pfad und kein Dateizugriff je Verbindung.

Beim Tausch wird die **ganze Kette** ersetzt, nicht nur das Blatt. Schlaegt das Laden fehl,
bleibt der alte, noch gueltige Zustand stehen — ein Fehlversuch darf kein Loch reissen.

## Gesperrte Agenten

Go prueft eingehende Client-Zertifikate im Handshake **nicht** gegen CRL oder OCSP; das muesste
man selbst einhaengen. Fuer ein Werkzeug, dessen Zertifikate niemand ausserhalb pruefen muss,
waere diese Maschinerie unverhaeltnismaessig.

Stattdessen: **kurze Laufzeiten fuer Agenten-Zertifikate plus eine eigene Sperrliste** (Seriennummer
oder Fingerabdruck), geprueft beim Verbindungsaufbau, zur Laufzeit austauschbar — dasselbe
`atomic.Value`-Muster wie oben. Das deckt den Regelfall durch Ablauf ab und den Notfall durch die
Liste. Das entspricht der Linie, die auch smallstep vertritt („passive Revokation") und die das
CA/Browser-Forum fuer kurzlebige Zertifikate ausdruecklich zulaesst.
