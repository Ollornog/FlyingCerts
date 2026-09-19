<p align="center"><img src="../docs/flying-certs.png" alt="FlyingCerts" width="250" height="250"></p>

<h1 align="center">FlyingCerts</h1>

<p align="center"><a href="../README.md">English</a> · <b>Deutsch</b></p>

<p align="right">
<a href="https://github.com/Ollornog/FlyingCerts/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/FlyingCerts/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
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

> **Kurz zur Einordnung:** FlyingCerts ist **keine CA** und **kein ACME-Server**. Es spricht
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

Binaries für Linux hängen an jedem [Release](https://github.com/Ollornog/FlyingCerts/releases):

```bash
curl -fsSLO https://github.com/Ollornog/FlyingCerts/releases/latest/download/SHA256SUMS
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
   gültig, kurzlebig, gebunden an diesen Namen und an die eigene CA des Vermittlers. **Nicht** an den
   CSR: der Agent erzeugt seinen Schlüssel erst beim Einlösen, es gibt zu diesem Zeitpunkt also nichts
   zu binden. ADR-6 hält diese Korrektur fest, statt sie zu verstecken — ein Versprechen, das ein
   Ablauf nicht halten kann, ist schlimmer als eines, das nie gegeben wurde.
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

## Laufzeit der Identitäten

Wie lange die Identität eines Agenten gilt, wird je Agent eingestellt; der Wert des Vermittlers
ist der Rückfall:

```yaml
broker:
  identity_lifetime: 30d        # Vorgabe für Agenten, die nichts sagen

agents:
  - name: gateway
    certificates: [gateway]
    mode: issue                 # erbt 30d

  - name: nightly-builder       # entsteht jede Nacht neu aus einem Abbild
    certificates: [gateway]
    mode: issue
    identity_lifetime: 1d

  - name: remote-appliance      # da müsste jemand hinfahren
    certificates: [internal-wildcard]
    mode: issue
    identity_lifetime: unlimited
```

Schreibbar, wie man darüber spricht: `1d`, `30d`, `1d12h`, `12h`. Ein blosses `30` wird abgelehnt —
für Sie heisst es Tage, für einen Parser Nanosekunden, und keine der beiden Lesarten ist es wert,
geraten zu werden.

**`unlimited` heisst „bis die Agenten-CA abläuft".** Ein Zertifikat ohne Ablauf gibt es nicht, das
ist also so nah dran, wie das Format erlaubt — und `agents` sagt das auch, statt etwas anderes zu
behaupten:

```
AGENT             MODE   LAST SEEN  LIFETIME   IDENTITY               CERTIFICATES
gateway           issue  2 h ago    30d        27 days                1
nightly-builder   issue  20 min     1d         22 h                   1
remote-appliance  issue  1 day      unlimited  until CA (2036-09-16)  1
```

### Was `unlimited` kostet

Ein Zweck dieses Werkzeugs war, langlebige gemeinsame Geheimnisse loszuwerden
([ADR-2](../backlog/ADR-2-mtls-statt-api-keys.md)). `unlimited` gibt genau diese Eigenschaft
wieder her, und das sollte deutlich dastehen:

- **Nur ein Widerruf nimmt die Identität zurück.** Ein ausgemusterter und nie widerrufener Host
  kann Jahre später noch Zertifikate abholen.
- **Ein kopierter Schlüssel bleibt gültig.** Bei 30 Tagen läuft eine Kopie von selbst aus, und
  jede Erneuerung ist eine regelmässige Gelegenheit, dass etwas auffällt. Unbegrenzt fällt diese
  Gelegenheit weg.

Es gibt die Einstellung trotzdem, weil der Gegenfall real ist: eine abgelaufene Identität auf einer
Maschine, die niemand erreicht, sperrt sie endgültig aus
([ADR-7](../backlog/ADR-7-kein-weg-zurueck-nach-ablauf.md)) — und ein Ausfall, der einen Menschen
mit einem Auto braucht, ist teurer als ein Zertifikat, das länger gilt. Die Entscheidung gehört
Ihnen; die Aufgabe des Werkzeugs ist, sie sichtbar zu halten. `check` meldet deshalb jede
unbegrenzte Identität — und schlägt deswegen **nicht** fehl. Ein Dauerzustand, der bei jedem Lauf
rot ist, bringt Leute dazu, die Ausgabe nicht mehr zu lesen, und dann geht die echte Warnung mit
unter.

Keine Identität überlebt die CA, die sie ausgestellt hat. Geprüft wird gegen das **tatsächliche**
Ende der CA, nicht gegen die Laufzeit, mit der sie erzeugt wurde: eine CA, die acht Jahre eines
Jahrzehnts hinter sich hat, hat zwei übrig — und ein Zertifikat, das seinen Aussteller überlebt,
hört ohne erkennbaren Grund auf zu funktionieren.

## Den Vermittler betreiben

`obtain` und `renew` brauchen nichts als einen Timer. Agenten zu bedienen ist ein eigener Befehl:

```bash
flying-certs-server -config config.yaml serve              # der mTLS-Endpunkt
flying-certs-server -config config.yaml token -agent web1  # einmalig, gibt die Marke aus
flying-certs-server -config config.yaml agents             # wer ist aufgenommen, und bis wann
flying-certs-server -config config.yaml check              # endet ungleich null, wenn etwas anliegt
```

```
AGENT  MODE   LAST SEEN  LIFETIME  IDENTITY     CERTIFICATES
web1   issue  2 h ago    30d       27 days      1
gw     share  9 days     30d       4 days left  2
```

`check` ist der Befehl für cron oder eine Überwachungssonde. Er meldet vier Lagen, die dringlichste
zuerst, und endet bei jeder davon ungleich null:

| | |
|---|---|
| **never enrolled** | konfiguriert, hat aber nie eine Identität abgeholt |
| **silent** | seit einer Woche nicht mehr gemeldet — vermutlich steht sein Timer |
| **lockout soon** | seine Identität läuft aus, bevor er sich plausibel selbst erneuern kann |
| **locked out** | Identität abgelaufen; er braucht jetzt von Hand eine neue Marke ([ADR-7](../backlog/ADR-7-kein-weg-zurueck-nach-ablauf.md)) |

Ein absichtlich widerrufener Agent taucht nicht als Problem auf, und eine bewusst auf `unlimited`
gestellte Identität ebenso wenig — die wird als Hinweis gedruckt und lässt den Rückgabewert in Ruhe.

```bash
flying-certs-server -config config.yaml revoke -agent web1 -reason "ausgemustert"
flying-certs-server -config config.yaml restore -agent web1
```

Ein Widerruf wirkt bei der nächsten Anfrage des Agenten, nicht erst beim nächsten Neustart.

## Sicherungen

Der ACME-Kontoschlüssel und die Agenten-CA lassen sich nicht neu erzeugen. Ist der erste weg,
gelingt nie wieder eine Erneuerung; ist die zweite weg, ist jeder Agent ausgesperrt und kommt nicht
von allein zurück.

```bash
flying-certs-server -config config.yaml backup -out /backup/broker-$(date +%F).tar.gz
flying-certs-server -config config.yaml backup-info -in /backup/broker-2026-09-20.tar.gz
flying-certs-server -config config.yaml restore-backup -in /backup/broker-2026-09-20.tar.gz
```

Das Archiv enthält private Schlüssel und sagt das auch. `-redact` lässt sie weg für eine Kopie zur
Fehlersuche — die ist als **nicht wiederherstellbar** gekennzeichnet, und `restore-backup` lehnt sie
mit Namen ab, statt auf halbem Weg zu scheitern. `backup-info` beantwortet „könnte ich hieraus
wirklich zurückspielen?" in einer Sekunde und endet ungleich null, wenn die Antwort nein lautet —
genau die Prüfung, die sich regelmäßig zu laufen lohnt.

Mehr als eine `tar`-Hülle ist das wegen des Tests: er zerstört den gesamten Zustand, spielt zurück,
öffnet alles neu von der Platte und **erneuert dann gegen die CA und liefert an einen Agenten aus,
der sich vor dem Ausfall eingeschrieben hat**. [ADR-16](../backlog/ADR-16-sicherung.md) erklärt,
warum — vier getrennte Sicherungsausfälle in einem vergleichbaren Projekt, jeder davon eine
Sicherung, die nur auf „die Dateien sind wieder da" geprüft worden war.

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

**Früh, und ehrlich darüber.** Die Schnittstellen sind nicht stabil, es gibt noch keine brauchbare
Veröffentlichung.

Alle sechs Meilensteine in [`backlog/`](../backlog/) sind erledigt. Der Vermittler holt und hält
Zertifikate, gibt sie über mTLS aus, führt Buch darüber, wer wann was abgeholt hat und wann welche
Identität ausläuft, warnt bevor sich ein Host aussperrt, und lässt sich sichern und zurückspielen.
Agenten schreiben sich mit einer einmaligen Marke ein, holen über mTLS und prüfen nach, ob ihr
Neuladen tatsächlich gewirkt hat.

**Ende zu Ende gegen eine echte CA belegt.** Zwei Läufe gegen Pebble, die Test-CA von Let's Encrypt,
bei jedem CI-Lauf: der Ausstellungsweg (Konto, DNS-01, Erneuerung mit Nennung des Vorgängers, ARI)
und der Wiederherstellungsweg (alles zerstören, zurückspielen, erneuern, ausliefern). Beide
scheitern, statt zu überspringen, wenn die Test-CA fehlt — ein Test, der still übersprungen wird,
ist Dekoration.

Die Entwurfsentscheidungen fielen **vor** dem Code, aus dem Studium dessen, was vergleichbare
Projekte falsch gemacht haben — jede steht als ADR in [`backlog/`](../backlog/) und benennt den
Fehler, den sie vermeidet. Wo sich eine als falsch herausstellte, sagt das ADR es, statt still
umgeschrieben zu werden. Wer anderer Meinung ist, findet die Begründung aufgeschrieben und kann
dagegen argumentieren.

MIT-Lizenz.

## Danksagung

Icon: <a href="https://www.flaticon.com/de/autoren/slidicon" target="_blank" rel="noopener">Zertifikat Icons erstellt von Slidicon - Flaticon</a>
