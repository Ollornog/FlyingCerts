<p align="center"><img src="../docs/flying-certs.png" alt="flying-certs" width="250" height="250"></p>

<h1 align="center">flying-certs</h1>

<p align="center"><a href="../README.md">English</a> · <b>Deutsch</b></p>

<p align="right">
<a href="https://github.com/Ollornog/flying-certs/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/flying-certs/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
<a href="../LICENSE"><img src="https://img.shields.io/badge/License-MIT-informational.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/go-1.27%2B-00ADD8.svg" alt="Go">
</p>

### Öffentlich vertrauenswürdige Zertifikate für Hosts, die das Internet nicht erreicht.

**Ein exponierter Host erledigt die ACME-Arbeit, die anderen kommen und fragen.** Deine internen
Maschinen liegen hinter NAT, in einem Mesh-VPN oder in einem Netz, das keine CA je erreicht — und
brauchen trotzdem Zertifikate, denen ein Browser traut: weil deine Domain im HSTS-Preload steht oder
weil deine Nutzer Telefone mitbringen, die dir nicht gehören.

- **Kein DNS-API-Token auf zwölf Maschinen?** → brauchst du nicht. Nur der Vermittler hält ihn.
- **Auch nicht denselben privaten Schlüssel auf zwölf Maschinen?** → dann lass es. Im Modus `issue` verlässt der Schlüssel den Host nie.
- **Wissen, welchem Host das Zertifikat ausgeht?** → der Vermittler weiss es, weil er jedes einzeln ausgestellt hat.
- **Auf jedem Host läuft schon eigenes ACME?** → dann brauchst du das hier nicht. Mach weiter so.

> **Kurz zur Einordnung:** flying-certs ist **keine CA** und **kein ACME-Server**. Es spricht
> stellvertretend für Hosts, die es selbst nicht können, mit einer echten ACME-CA und reicht das
> Ergebnis an den Host weiter, der gefragt hat. Es ist also **kein Ersatz** für step-ca oder
> Vault PKI — die geben dir eine *eigene* Vertrauenswurzel. Dieses hier holt Zertifikate, denen die
> *Öffentlichkeit* bereits traut.

**Wie es zusammenspielt:**

```
        ACME / DNS-01
   CA ◀──────────────▶  Vermittler (exponiert)      Agent (intern)
                        · holt + erneuert           · fordert sein Zertifikat an
                        · autorisiert jede Anfrage ◀── · legt es ab
                        · schreibt wer/was/wann        · lädt den Dienst neu
                        · verfolgt Ablauf je Host      · prüft, ob das wirkte
```

**Was du bekommst:**

- 🔐 **mTLS ohne geteiltes Geheimnis** — ein einmaliges Token zur Aufnahme, danach ein eigenes Zertifikat
- 📜 **Zwei Ausliefermodi** — ein Zertifikat je Host (empfohlen) oder ein geteiltes
- 🛡️ **Namens-Autorisierung** — ein Host bekommt Zertifikate für *seine* Namen und keine anderen
- 📋 **Eine Aufzeichnung, die etwas wert ist** — die Identität kommt aus dem Client-Zertifikat, nicht aus einem Header
- ⏰ **Ablauf je Host** — mit Warnung, bevor ein Host sich aussperrt
- 🔁 **Erneuerung nach ARI** — die CA sagt wann, mit vernünftigem Rückfall, wenn sie es nicht tut
- ✅ **Geprüftes Neuladen** — der Agent schaut, was der Dienst *tatsächlich ausliefert*, nicht auf den Rückgabewert

---

## Installation

Binaries für Linux hängen an jedem [Release](https://github.com/Ollornog/flying-certs/releases):

```bash
curl -fsSLO https://github.com/Ollornog/flying-certs/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS         # prüfen, bevor du es ausführst
```

Oder aus den Quellen bauen (Go 1.27+):

```bash
go build ./cmd/flying-certs-server
go build ./cmd/flying-certs-agent
```

## Schnelleinstieg

Konfigurationsdatei schreiben (kommentierte Vorlage:
[`examples/config.yaml`](../examples/config.yaml)), dann:

```bash
export DNSUPDATE_NAMESERVER=ns.example.com:53      # Zugangsdaten des Anbieters,
export DNSUPDATE_TSIG_SECRET=…                     # aus der Umgebung, nicht aus der Datei

flying-certs-server -config config.yaml register   # einmalig: ACME-Konto anlegen
flying-certs-server -config config.yaml obtain     # holen, was noch fehlt
flying-certs-server -config config.yaml list       # nachsehen, was da ist
```

```
NAME               DOMAINS                   EXPIRES     REMAINING
gateway            gateway.example.com       2026-12-18  89 days left
internal-wildcard  *.internal.example.com    2026-12-18  89 days left
```

`renew` läuft danach aus einem Timer. Es fragt die CA, wann sie gefragt werden
möchte (ARI), und erneuert sonst nach zwei Dritteln der Laufzeit — derselbe
Timer trägt also 90-Tage- wie 6-Tage-Zertifikate:

```bash
flying-certs-server -config config.yaml renew
```

Fang mit `directory: staging` an — dessen Zertifikate sind wertlos und die
Rate-Limits nachsichtig, genau richtig, solange du herausfindest, ob deine
DNS-Zugangsdaten stimmen.

## Wie ein Host dazukommt

Kein langlebiges geteiltes Geheimnis, und kein Login auf dem Vermittler.

1. Du stellst auf dem Vermittler ein **Bootstrap-Token** für einen benannten Host aus. Einmalig
   gültig, kurzlebig, gebunden an diesen Namen **und** an die Anfrage, mit der es eingelöst wird.
2. Der Agent löst es **einmal** ein und erhält sein eigenes Client-Zertifikat.
3. Ab dann weist er sich per **mTLS** aus — etwas anderes wird nicht angenommen.
4. Er erneuert dieses Zertifikat rechtzeitig, damit er sich nicht aussperrt.

Läuft es *doch* ab, gibt es keinen automatischen Rückweg: ein abgelaufenes Zertifikat kann sich nicht
mehr ausweisen, um seinen eigenen Ersatz zu erbitten. Das ist Absicht — und der Vermittler warnt
lange vorher.

## Zwei Ausliefermodi

Wählbar je Host oder Gruppe. Sie sind nicht gleich gut, und das steht hier auch so.

**`issue` — ein eigenes Zertifikat** *(empfohlen)*
Der Agent erzeugt seinen Schlüssel lokal und schickt nur einen CSR. **Es reist nie ein privater
Schlüssel.** Der Vermittler prüft jeden Namen in diesem CSR gegen das, was diesem Host zusteht, und
holt dann das Zertifikat. Weil je Host ausgestellt wird, hat „wann läuft dieser Host ab" eine echte
Antwort.

**`share` — ein geteiltes Zertifikat**
Der Vermittler gibt ein Zertifikat *samt privatem Schlüssel* an jeden dafür berechtigten Host.
Einfacher, und manchmal die einzige Möglichkeit — aber der Schlüssel reist, und alle Hosts, die ihn
halten, teilen ein Schicksal. Ablauf ist dann eine Eigenschaft des Zertifikats, nicht des Hosts.

## DNS-Anbieter

DNS-01 ist die einzige Challenge, die dieses Werkzeug nutzt — es muss also einen TXT-Eintrag
schreiben können. Einkompiliert sind:

`acmedns` · `cloudflare` · `desec` · `digitalocean` · `hetzner` · `rfc2136` · `route53`

Das sind sieben von legos über 200, und die Auswahl ist Absicht: alle zu importieren kostet
**1546 gebaute Pakete statt 424** und zieht die SDKs von AWS, Azure, Google Cloud, Alibaba,
Akamai und weiteren mit. Für ein Programm, dessen Aufgabe die Verwahrung privater Schlüssel ist,
arbeitet diese Lieferkette gegen den Zweck.

**Dein Anbieter fehlt? Du sitzt trotzdem nicht fest** — und genau das macht die kurze Liste
vertretbar:

- **`rfc2136`** spricht mit jedem üblichen autoritativen DNS-Server (BIND, Knot, PowerDNS) per
  dynamischem Update mit TSIG-Schlüssel — und ein TSIG-Schlüssel lässt sich auf einen einzelnen
  Eintragsnamen einschränken.
- **`acmedns`** delegiert die Challenge-Einträge per CNAME an einen winzigen Dienst, der sonst
  nichts kann. Es braucht **gar keinen Anbieter-Token**, was ohnehin das bessere
  Sicherheitsmodell ist als ein vollmächtiger DNS-API-Token.

Beides ist einem breiten Anbieter-Token vorzuziehen. Wer trotzdem seinen eigenen will, ergänzt
eine Import-Zeile in `internal/acme/providers.go` und baut neu — die Begründung steht in
[ADR-14](../backlog/ADR-14-dns-anbieter-auswahl.md).

## Tests & CI

```bash
scripts/check.sh            # das volle Tor: gofmt, vet, go test -race, Hygiene, Rückstände
scripts/check.sh --fast     # ohne Race-Detektor (nur wenn es eilt)
```

Das Tor fährt zweierlei nebeneinander, weil der Code Go ist und die Repo-Hygiene aus einer geteilten
Python-Basis kommt:

- **`go test -race ./...`** — der Race-Detektor gehört in den Normallauf, nicht in einen Sonderlauf:
  der Vermittler bedient viele Agenten gleichzeitig und teilt sich Zertifikatszustand.
- **`tests/test_repo.py`** — bewacht die Hausordnung: Version in `internal/version` passt zum
  Changelog, keine private Infrastruktur, keine Geheimnisse, keine Schlüsseldateien, Actions per
  Commit-SHA gepinnt, `permissions:` in jedem Workflow, deutsche und englische Dokumente in gleicher
  Gestalt.

**Vor jedem Push** — ein Tor, lokal:

```bash
git config core.hooksPath .githooks   # einmal je Klon: der pre-push-Hook fährt das Tor
scripts/check.sh
```

**GitHub Actions** fährt dasselbe Tor bei jedem Push **zweimal**. Ein Test, der beim zweiten Lauf rot
wird, ist kaputt — nicht der Code. So ist die Wiederholbarkeit vorgeführt statt behauptet.

## Stand

**Früh, und ehrlich darüber.** Die Schnittstellen sind nicht stabil, ein brauchbares Release gibt es
noch nicht.

Der Vermittler läuft als Satz von Befehlen: `register`, `obtain`, `renew`, `list`. Alles darunter
ist getestet — atomares Schreiben mit durchgesetzten Rechten, Zertifikatsuntersuchung, ein
ACME-Konto, das nie stillschweigend ersetzt wird, ARI-gesteuerte Erneuerung mit Rückfall auf einen
Anteil der Laufzeit, serialisierte DNS-01-Challenge-Einträge und der Protokoll-Filter.

**Durchgängig gegen eine echte CA bewiesen.** Der volle Weg — Konto anlegen, per DNS-01 holen, mit
Nennung des Vorgängers erneuern, die CA nach ihrem Wunschzeitpunkt fragen — läuft bei jedem CI-Lauf
gegen Pebble, die Test-CA von Let's Encrypt. Dort scheitert er, statt sich zu überspringen, wenn die
Test-CA fehlt: ein Test, der still übersprungen wird, ist Dekoration.

Was noch fehlt: die mTLS-Schnittstelle und der Agent, Hosts können ihre Zertifikate also noch nicht
anfordern. Das sind die Meilensteine **M-2** bis **M-5** in [`backlog/`](../backlog/).

Die Architekturentscheidungen fielen **vor** dem Code, aus der Untersuchung dessen, was vergleichbare
Projekte falsch gemacht haben — jede ist als ADR in [`backlog/`](../backlog/) festgehalten und nennt
den Fehler, den sie vermeidet. Wer eine davon für falsch hält, findet die Begründung aufgeschrieben
und kann dagegen argumentieren.

MIT-Lizenz.

## Danksagung

Icon: <a href="https://www.flaticon.com/de/autoren/slidicon" target="_blank" rel="noopener">Zertifikat Icons erstellt von Slidicon - Flaticon</a>
