---
id: ADR-18
type: Decision
title: Der Geraeteschluessel ist der Standardweg — und der Weg zurueck
status: erledigt
tags: [sicherheit, betrieb, aufnahme]
created: 2026-09-20
---

## Die Frage, die alles ausgeloest hat

> „Ich fahre in Urlaub und fahre einen Server runter. Der bekommt dann keine Zertifikate und
> sperrt sich aus."

Das war zutreffend und hatte keine Abhilfe. Eine abgelaufene Identitaet kann sich nicht
ausweisen, um ihren Ersatz anzufordern — der Henne-Ei-Fall aus
[ADR-7](ADR-7-kein-weg-zurueck-nach-ablauf.md). Eine Bootstrap-Marke hilft nicht: die ist nach
fuenf Minuten ebenfalls tot. Uebrig blieb: jemand meldet sich auf dem Host an.

Die bisherigen Antworten waren beide schlecht. **Lange Laufzeit** verschiebt das Problem nur und
macht eine gestohlene Identitaet monatelang wertvoll. **`unlimited`**
([ADR-17](ADR-17-einstellbare-laufzeit.md)) schafft es ab, indem es die Selbstbegrenzung opfert —
ausgerechnet die Eigenschaft, wegen der das Projekt keine API-Schluessel benutzt.

## Entschieden

**Der Host haelt ein dauerhaftes Schluesselpaar. Der Vermittler kennt den oeffentlichen Teil.
Damit kann der Host jederzeit eine Identitaet anfordern — auch nach Monaten im ausgeschalteten
Zustand.** Das ist `authorized_keys`, und es funktioniert aus demselben Grund: **das Geheimnis
reist nicht**, also gibt es nirgends eine Kopie davon zu stehlen.

```yaml
agents:
  - name: gateway
    public_key: "SHA256:3zCYV58KfoUQglgefqPRMl1I+EvvbaaGpYAUuLjK8Y4"
    identity_lifetime: 1d
```

**Zwei Schluessel, nicht einer** — das ist der Kern:

| | Geraeteschluessel | Identitaet |
|---|---|---|
| Laufzeit | unbegrenzt | kurz (Tage) |
| Benutzt | selten, nur zum Anfordern | staendig |
| Verlaesst den Host | **nie** | der private Teil nie, das Zertifikat ist oeffentlich |
| Entzug | Zeile aus der Konfiguration, oder `revoke` | laeuft von selbst aus |

Ein Leck der Identitaet ist einen Tag wert. Beide zu einem Schluessel zusammenzulegen hiesse, das
langlebige Geheimnis in den taeglichen Verkehr zu geben — der halbe Weg zurueck zum API-Schluessel.
Der Vermittler **lehnt** einen CSR ab, der auf dem Geraeteschluessel beruht; die Trennung ist
erzwungen, nicht empfohlen.

**Der Fingerabdruck geht ueber den oeffentlichen Schluessel** (SPKI-SHA256, Format wie OpenSSH),
nicht ueber ein Zertifikat. Der Agent stellt sich fuer jede Verbindung ein frisches
selbstsigniertes Zertifikat aus; ein Zertifikats-Fingerabdruck waere damit bei jedem Verbindungs-
aufbau ein anderer und der Wert in der Konfiguration sofort veraltet.

## Der Preis: die TLS-Schicht prueft nicht mehr selbst

Bisher stand `VerifyClientCertIfGiven` mit `ClientCAs` in der TLS-Konfiguration — die Bibliothek
brach den Handshake ab, wenn ein vorgelegtes Zertifikat nicht zur eigenen CA kettete, und ein
Handler konnte sich darauf verlassen. **Das geht nicht mehr:** das Geraete-Zertifikat ist
absichtlich *nicht* von unserer CA, und `VerifyClientCertIfGiven` wuerde es nie bis zu einem
Handler kommen lassen.

Also `RequestClientCert` und die Pruefung **in diesem Paket**, je Route genau eine:

- `verifiedAgent` prueft die Kette gegen unsere CA, die Gueltigkeit **jetzt** (das ist, was eine
  abgelaufene Identitaet wirklich stoppt statt sie nur alt aussehen zu lassen) und die
  Schluesselverwendung `clientAuth` (sonst waere das Server-Zertifikat des Vermittlers, aus
  derselben CA, eine gueltige Anmeldung).
- `deviceFingerprint` prueft gar nichts am Zertifikat — es ist nur eine Huelle um einen
  oeffentlichen Schluessel. Autorisiert wird gegen die Fingerabdruecke in der Konfiguration.

**Was die TLS-Schicht weiterhin garantiert und deshalb hier nicht nachgebaut wird:** wer ein
Zertifikat vorlegt, hat den Besitz des privaten Schluessels bewiesen. Go prueft die
`CertificateVerify`-Signatur in **jedem** `ClientAuth`-Modus. Zertifikate sind oeffentlich; ein
gestohlenes ist ohne Schluessel wertlos.

„Wir pruefen selbst" ist die Formulierung, hinter der Authentifizierungsluecken entstehen. Darum
gibt es `verify_test.go`: selbstsigniert mit fremdem Namen, fremde CA, abgelaufen, Server-
Zertifikat derselben CA, gar keins — jeder Fall einzeln, jeder muss abgelehnt werden.

## Folgen fuer den Rest

- **Die Laufzeit darf kurz sein.** Der Grund fuer lange Laufzeiten und fuer `unlimited` war die
  Aussperr-Gefahr; die ist weg. Empfehlung in Beispielen und README: `1d` mit Geraeteschluessel.
- **`run` heilt sich selbst.** Fehlt die Identitaet oder ist sie abgelaufen, holt der Agent
  stillschweigend eine neue — kein Eingriff, kein Login.
- **Die Marke bleibt**, als bequemer Weg fuer den, der keinen Fingerabdruck vom Host holen will.
  Sie ist jetzt die Alternative, nicht der Hauptweg.
- **Widerruf wirkt weiter.** Ein widerrufener Agent wird auch mit gueltigem Geraeteschluessel
  abgewiesen — sonst waere `revoke` ausgerechnet fuer die Hosts wirkungslos, die dauerhafte
  Zugangsdaten halten.

## Bewusst nicht

- **Kein Vertrauen beim ersten Kontakt (TOFU).** Der Vermittler nimmt keinen unbekannten Schluessel
  an, auch nicht beim ersten Mal. Ein Fingerabdruck wird eingetragen, von einem Menschen.
- **Kein Ablauf fuer den Geraeteschluessel.** Ein Ablauf haette genau das Problem zurueckgebracht,
  das dieses ADR loest. Entzogen wird durch Entfernen oder `revoke`.
- **Kein Ersetzen eines vorhandenen Geraeteschluessels durch `keygen`.** Ueberschreiben wuerde dem
  Host lautlos das Einzige nehmen, was ihn zurueckholt — und wie Erfolg aussehen.
