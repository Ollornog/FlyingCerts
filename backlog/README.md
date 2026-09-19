# Backlog

<!-- GENERIERT von scripts/_backlog.py — nicht von Hand pflegen. Neu bauen: `python3 scripts/_backlog.py index` -->

Die Wahrheit sind die Einzeldateien in diesem Verzeichnis; diese Seite ist ihr Abzug.
Konventionen: [README-KONVENTION.md](README-KONVENTION.md).

## Meilensteine

* ☑ **[M-1](M-1-vermittler-grundgeruest.md)** Vermittler-Grundgeruest — Zertifikate holen und halten — 2/2 erledigt
* ☑ **[M-2](M-2-bootstrap-und-mtls.md)** Aufnahme eines Agenten — Bootstrap-Token und mTLS — 1/1 erledigt
* ☐ **[M-3](M-3-ausstellung-je-agent.md)** Modus `issue` — je Agent ein eigenes Zertifikat — noch keine Aufgaben
* ☐ **[M-4](M-4-agent.md)** Agent — anfordern, ablegen, neu laden — noch keine Aufgaben
* ☐ **[M-5](M-5-audit-und-ablauf.md)** Aufzeichnung und Ablaufverfolgung — 0/1 erledigt

## Aufgaben

* ☑ **[T-1](T-1-gesundheit-prueft-paar.md)** Gesundheitspruefung eines Zertifikats prueft das PAAR, nicht nur das Zertifikat · M-1
* ☑ **[T-2](T-2-ratenbegrenzung-nach-pruefung.md)** Ratenbegrenzung erst nach der Identitaetspruefung, nie auf ungepruefte Eingaben · M-2
* ☐ **[T-3](T-3-sicherung-faehrt-erneuerung.md)** Der Sicherungs-Test spielt zurueck UND faehrt danach eine Erneuerung · M-5
* ☑ **[T-4](T-4-ende-zu-ende-gegen-pebble.md)** Ende-zu-Ende-Lauf gegen eine Test-CA (Pebble) · M-1

## Entscheidungen (ADR)

* ☑ **[ADR-1](ADR-1-go-als-sprache.md)** Go als Implementierungssprache
* ☑ **[ADR-2](ADR-2-mtls-statt-api-keys.md)** mTLS mit einmaligem Bootstrap-Token statt langlebiger API-Schluessel
* ☑ **[ADR-3](ADR-3-zwei-ausliefermodi.md)** Zwei Ausliefermodi, `issue` ist der empfohlene
* ☑ **[ADR-4](ADR-4-kein-acme-nach-innen.md)** Agenten sprechen nicht ACME mit dem Vermittler
* ☑ **[ADR-5](ADR-5-reload-wirkung-pruefen.md)** Nach dem Neuladen wird die Wirkung geprueft, nicht der Rueckgabewert
* ☑ **[ADR-6](ADR-6-bootstrap-parameter.md)** Bootstrap-Token — Parameter und Bindungen, gelernt an step-ca
* ☑ **[ADR-7](ADR-7-kein-weg-zurueck-nach-ablauf.md)** Ein abgelaufenes Agenten-Zertifikat erneuert sich nicht selbst
* ☑ **[ADR-8](ADR-8-speicher.md)** Speicher — reines Go, Migrationen von Anfang an, eine Quelle fuer Zustand
* ☑ **[ADR-9](ADR-9-dns01-nebenlaeufigkeit.md)** DNS-01 wird je Zone serialisiert, die Wartezeit ist eingestellt statt erraten
* ☑ **[ADR-10](ADR-10-acme-konto-und-lego.md)** Ein ACME-Konto, dauerhaft gespeichert — und lego mit eigenen Zeitgrenzen
* ☑ **[ADR-11](ADR-11-zeitrechnung.md)** Restlaufzeiten werden nie auf ganze Tage gerundet
* ☑ **[ADR-12](ADR-12-kein-selbstheilen.md)** Bei erkannter Unstimmigkeit wird gemeldet, nicht selbst geheilt
* ☑ **[ADR-13](ADR-13-go-handwerk.md)** Handwerk — lego v5, atomares Schreiben, Zertifikatstausch im Betrieb
* ☑ **[ADR-14](ADR-14-dns-anbieter-auswahl.md)** Eine kuratierte Auswahl von DNS-Anbietern statt aller 200
* ☑ **[ADR-15](ADR-15-eigene-ca-nur-fuer-agenten.md)** Der Vermittler ist doch eine CA — aber nur für Agenten-Ausweise
