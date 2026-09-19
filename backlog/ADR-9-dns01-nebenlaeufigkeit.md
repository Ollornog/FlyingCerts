---
id: ADR-9
type: Decision
title: DNS-01 wird je Zone serialisiert, die Wartezeit ist eingestellt statt erraten
status: erledigt
tags: [acme, dns01, nebenlaeufigkeit]
created: 2026-09-19
---

## Kontext

Bei DNS-01 legt der Anfragende einen `_acme-challenge`-Eintrag an. Holt der Vermittler mehrere
Zertifikate gleichzeitig, greifen mehrere Vorgaenge nach **derselben** Ressource.

Cert Warden hat daran lange laboriert (Issues #23 und #74): parallele Loeser kollidierten, wenn
eine Domain und ihre Platzhalter-Form zusammen bestellt wurden oder wenn mehrere Domains per
CNAME auf **dasselbe** Delegationsziel zeigen. Fehlerbild: `already exists and content does not
match`, haengende Bestellungen. Es brauchte mehrere Anlaeufe und einen Umbau der Loeser-Logik
(v0.24.8); fuer den Fall „viele Domains, ein gemeinsames CNAME-Ziel" gilt es laut externem
Fachfeedback bis heute nicht als vollstaendig geloest.

Die zweite Lehre betrifft das Warten: Cert Warden baute erst eine aktive Propagationspruefung,
fand sie *„somewhat hit or miss depending on provider"* und **entfernte sie wieder** (v0.28.0)
zugunsten einer je Anbieter einstellbaren festen Wartezeit.

## Wahl

- **Zugriffe auf dieselbe Challenge-Ressource werden serialisiert**, nicht parallelisiert. Der
  Schluessel dafuer ist das **tatsaechliche Ziel des Eintrags** (nach CNAME-Aufloesung), nicht
  der angefragte Name — sonst greift die Sperre am Problem vorbei.
- **Feste, je Anbieter einstellbare Wartezeit** statt einer selbstgebauten
  Propagationsintelligenz. Wer es genauer will, kann die autoritativen Namensserver direkt
  befragen — als ausdrueckliche Einstellung, nicht als stilles Standardverhalten.
- Ein Fehlschlag laesst das **vorhandene** Zertifikat unberuehrt und raeumt seinen
  Challenge-Eintrag auf.

## Konsequenzen

- Das Holen mehrerer Zertifikate dauert laenger, wenn sie sich eine Zone teilen. Das ist der
  Preis und wird dokumentiert.
- Die Tests brauchen einen Fall mit zwei gleichzeitigen Bestellungen auf dieselbe Zone — sonst
  faellt genau dieser Fehler erst im Betrieb auf.
