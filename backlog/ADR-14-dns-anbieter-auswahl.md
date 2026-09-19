---
id: ADR-14
type: Decision
title: Eine kuratierte Auswahl von DNS-Anbietern statt aller 200
status: erledigt
tags: [architektur, sicherheit, abhaengigkeiten, dns]
created: 2026-09-19
---

## Kontext

lego bringt über 200 DNS-Anbieter mit. Ein einziger Import (`providers/dns`) macht sie alle
verfügbar — und zieht ihre SDKs mit. Gemessen an diesem Projekt:

| | gebaute Pakete | davon Cloud-SDKs |
|---|---|---|
| `providers/dns` (alle) | **1546** | 163 |
| kuratierte Auswahl (7) | **424** | 59 |

1319 der 1546 Pakete stammen aus fremden Modulen: AWS, Azure, Google Cloud, Alibaba, Akamai,
Tencent, Huawei, Oracle und weitere — für ein Werkzeug, dessen Zweck die Verwahrung privater
Schlüssel ist.

## Die Abwägung

Das Argument für „alle" ist der Universalanspruch: es soll überall laufen. Das Argument dagegen
ist, dass ein Sicherheitswerkzeug mit 1319 fremden Paketen seinem eigenen Zweck widerspricht.
Jedes davon ist ein Weg, auf dem fremder Code in den Prozess gelangt, der die Schlüssel hält.

Der Ausweg liegt in zwei der Anbieter selbst:

- **RFC2136** spricht jeder gängige autoritative DNS-Server (BIND, Knot, PowerDNS).
- **acme-dns** ist das Delegationsverfahren: ein CNAME zeigt auf einen winzigen DNS-Dienst, der
  nur Challenge-Einträge kennt.

Wer seinen Anbieter nicht in der Liste findet, ist mit diesen beiden **nie blockiert** — und
fährt dabei sogar das bessere Sicherheitsmodell, weil kein vollmächtiger Anbieter-Token nötig ist.

## Wahl

Sieben einkompilierte Anbieter: `cloudflare`, `route53`, `digitalocean`, `hetzner`, `desec`,
**`rfc2136`** und **`acmedns`**.

Wer einen weiteren braucht, ergänzt **eine Zeile** in `internal/acme/providers.go` und baut neu.
Das steht in der Doku, mitsamt der Begründung — damit es als bewusster Schritt erscheint und
nicht als Mangel.

## Konsequenzen

- Der Bau ist um rund drei Viertel leichter (1546 → 424 Pakete), das Abbild kleiner, die Lieferkette überschaubar.
- Ein Anbieter, den wir nicht kennen, kostet den Nutzer einen Neubau. Das ist der Preis, und er
  ist in der README genannt statt versteckt.
- Die Liste wird **nicht** stillschweigend wachsen. Ein neuer Anbieter ist eine Entscheidung mit
  Begründung, kein „schadet ja nicht" — sonst steht die Zahl in zwei Jahren wieder bei 1546.
