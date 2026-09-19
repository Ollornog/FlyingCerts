<p align="center"><img src="../docs/flying-certs.png" alt="flying-certs" width="250" height="250"></p>

<h1 align="center">flying-certs</h1>

<p align="center"><a href="../README.md">English</a> · <b>Deutsch</b></p>

<p align="right">
<a href="https://github.com/Ollornog/flying-certs/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/flying-certs/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
<a href="../LICENSE"><img src="https://img.shields.io/badge/License-MIT-informational.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/go-1.27%2B-00ADD8.svg" alt="Go">
</p>

### Öffentlich vertrauenswürdige Zertifikate für Hosts, die das Internet nicht erreicht.

Einer deiner Hosts steht exponiert und kann mit einer CA sprechen. Die anderen nicht — sie liegen
im internen Netz, hinter NAT oder in einem Mesh-VPN. Trotzdem brauchen sie Zertifikate, denen ein
Browser traut: weil deine Domain im HSTS-Preload steht, oder weil deine Nutzer Telefone
mitbringen, die dir nicht gehören.

**flying-certs** stellt einen Vermittler auf den exponierten Host. Er holt Zertifikate per ACME
über eine DNS-01-Challenge, und die internen Hosts **kommen und fordern ihres an**. Der Vermittler
weiss, wer wann was angefragt hat — und kann deshalb auch sagen, welchem Host das Zertifikat
demnächst ausgeht.

```
        ACME / DNS-01
   CA ◀──────────────▶  Vermittler (exponiert)      Agent (intern)
                        · holt + erneuert           · fordert sein Zertifikat an
                        · autorisiert jede Anfrage ◀── · legt es ab
                        · schreibt wer/was/wann        · lädt den Dienst neu
                        · verfolgt Ablauf je Host      · prüft, ob das wirkte
```

## Warum nicht einfach die Dateien kopieren

Genau das machen die meisten, und es trägt — bis es das nicht mehr tut:

- **Der private Schlüssel reist mit.** Ein geteiltes Wildcard auf einem Dutzend Hosts heisst: ein
  übernommener Host entblösst jeden Dienst unter diesem Namen — und ein Widerruf legt sie alle
  gleichzeitig still.
- **Niemand autorisiert die Anfrage.** Ein Kopierauftrag, der ein Verzeichnis lesen darf, darf es
  *ganz* lesen. Der Filter sitzt üblicherweise beim Client — auf der falschen Seite.
- **Niemand merkt, wenn es aufhört.** Ein Kopierauftrag, der still nichts tut, sieht genauso aus wie
  einer, für den nichts zu tun war — bis in der Produktion ein Zertifikat abläuft.

flying-certs ist die Antwort auf diese drei, in dieser Reihenfolge.

## Wie ein Host dazukommt

Kein langlebiges geteiltes Geheimnis, und kein Login auf dem Vermittler.

1. Du stellst auf dem Vermittler ein **Bootstrap-Token** für einen benannten Host aus. Einmalig
   gültig und kurzlebig.
2. Der Agent löst es **einmal** ein und erhält sein eigenes Client-Zertifikat.
3. Ab dann weist er sich per **mTLS** aus — etwas anderes wird nicht angenommen. Der Vermittler
   kennt jeden Aufrufer kryptografisch; erst das macht die Aufzeichnung überhaupt etwas wert.
4. Der Agent erneuert sein Client-Zertifikat rechtzeitig, damit er sich nicht selbst aussperrt.

## Zwei Ausliefermodi

Wählbar je Host oder Gruppe. Sie sind nicht gleich gut, und die Doku sagt das auch.

**`issue` — ein eigenes Zertifikat** *(empfohlen)*
Der Agent erzeugt seinen Schlüssel lokal und schickt nur einen CSR. **Es reist nie ein privater
Schlüssel.** Der Vermittler holt für diesen Host ein Zertifikat von der CA und gibt es zurück. Weil
je Host ausgestellt wird, ist „wann läuft dieser Host ab" eine echte Frage mit echter Antwort.

**`share` — ein geteiltes Zertifikat**
Der Vermittler gibt ein Zertifikat *samt privatem Schlüssel* an jeden dafür berechtigten Host.
Einfacher, und manchmal die einzige Möglichkeit — aber der Schlüssel reist, und alle Hosts, die ihn
halten, teilen ein Schicksal. Ablauf ist dann eine Eigenschaft des Zertifikats, nicht des Hosts.

## Stand

Früh. Die Schnittstellen sind noch nicht stabil. Was geplant ist und welche Entscheidungen bereits
gefallen sind, steht in [`backlog/`](../backlog/); was ausgeliefert wurde, in
[`CHANGELOG.md`](../CHANGELOG.md).

## Was es nicht ist

- **Keine CA.** Es signiert nichts selbst. Es spricht mit einer echten ACME-CA und reicht das
  Ergebnis weiter.
- **Kein ACME-Server.** Agenten sprechen das flying-certs-Protokoll, nicht ACME. Ein fremdes
  Zertifikat über ACME auszuliefern geht nicht — ACME signiert den CSR, den der Client erzeugt hat,
  und ein Leaf-Zertifikat kann nichts signieren.
- **Kein Ersatz dafür, jeden Host selbst ACME sprechen zu lassen.** Wenn deine Hosts eine CA
  erreichen *und* ihre DNS-Zugangsdaten sicher halten können, mach das. Das hier ist für den Fall,
  dass sie es nicht können.

## Installation

Binaries für Linux hängen an jedem [Release](https://github.com/Ollornog/flying-certs/releases).
Prüfe, was du geladen hast:

```bash
sha256sum -c SHA256SUMS
```

## Dokumentation

- [Mitwirken](CONTRIBUTING.de.md) · [Sicherheitsrichtlinie](SECURITY.de.md) · [Verhaltenskodex](CODE_OF_CONDUCT.de.md)
- [Backlog und Entscheidungen](../backlog/)

## Lizenz

[MIT](../LICENSE) — © 2026 ollornog
