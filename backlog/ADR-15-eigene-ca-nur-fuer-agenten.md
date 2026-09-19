---
id: ADR-15
type: Decision
title: Der Vermittler ist doch eine CA — aber nur für Agenten-Ausweise
status: erledigt
tags: [architektur, mtls, sicherheit, ca]
created: 2026-09-19
---

## Kontext

[ADR-4](ADR-4-kein-acme-nach-innen.md) sagt „keine CA", und die README sagt es auch. Für mTLS
braucht es aber zwingend eine: ein Client-Zertifikat muss von jemandem signiert sein, dem der
Vermittler traut. Das ist kein Widerspruch, sondern eine Zweiteilung, die man aussprechen muss,
sonst liest sich der Code, als hätte jemand die eigene Regel vergessen.

## Die Trennung

**Zwei Welten, die sich nie berühren:**

| | öffentliche Zertifikate | Agenten-Ausweise |
|---|---|---|
| ausgestellt von | einer echten ACME-CA | dem Vermittler selbst |
| vertraut von | der ganzen Welt | ausschliesslich dem Vermittler |
| wofür | die Dienste, die Agenten betreiben | die Frage „wer fragt hier an?" |
| Laufzeit | was die CA gibt | kurz, weil billig erneuerbar |

Der Vermittler ist also **keine CA für irgendetwas, das ein Browser sieht**. Seine
Ausweis-Wurzel steht in keinem Trust Store und soll dort nie stehen. Sie beantwortet genau eine
Frage, und zwar nur sich selbst: Ist dieser Anrufer der Agent, für den er sich ausgibt?

## Konsequenzen

- Die Ausweis-Wurzel wird **nie** in eine Antwort an einen Agenten gemischt und taucht in keinem
  ausgelieferten Bündel auf. Ein Agent, der sie versehentlich seinem Dienst unterschiebt, würde
  Besuchern ein Zertifikat zeigen, dem niemand traut.
- Agenten-Ausweise sind **kurzlebig** (Vorgabe 30 Tage). Das ist die eigentliche Sperre: eine
  Sperrliste fängt den Notfall, Ablauf fängt den Regelfall. Go prüft im Handshake ohnehin weder
  CRL noch OCSP, und diese Maschinerie für ein geschlossenes Zwei-Parteien-Verhältnis aufzubauen
  wäre unverhältnismässig ([ADR-13](ADR-13-go-handwerk.md)).
- Der Preis steht in [ADR-7](ADR-7-kein-weg-zurueck-nach-ablauf.md): Wer 30 Tage aus ist, muss neu
  aufgenommen werden. Deshalb erneuert der Agent früh und der Vermittler warnt vorher.
- Die Wurzel liegt getrennt von allem anderen und wird nie ausgeliefert — sie ist das einzige
  Geheimnis, dessen Verlust die Aufnahme aller Agenten wertlos macht.
