# Sicherheitsrichtlinie

<a href="../SECURITY.md">English</a> · <b>Deutsch</b>
<br /><br />

## Eine Schwachstelle melden

Bitte melde Sicherheitsprobleme **vertraulich**, nicht als öffentliches Issue.

- Bevorzugt: GitHubs [private Schwachstellenmeldung](https://github.com/Ollornog/FlyingCerts/security/advisories/new)
- Alternativ per E-Mail: flying-certs-github@ollornog.de

Bitte schreib dazu, was du getan hast, was du erwartet hast und was stattdessen passiert ist, dazu
die Version oder den Commit, den du geprüft hast. Ein minimales Beispiel hilft mehr als alles andere.

## Was du erwarten kannst

- **Eine Rückmeldung binnen 14 Tagen.** Dieses Projekt pflegt eine Person in ihrer Freizeit — das
  ist die Zusage, die sich halten lässt, deshalb steht genau die hier.
- Eine Einschätzung, ob die Meldung bestätigt ist, und wenn ja, eine Behebung oder eine
  dokumentierte Abmilderung.
- Nennung in den Release-Notes, sofern dir das recht ist.

## Unterstützte Versionen

Solange das Projekt unter 1.0 steht, erhält nur das jeweils neueste Release Korrekturen.

## Wofür wir uns besonders interessieren

Dieses Projekt hantiert mit privaten Schlüsseln und gibt Zugangsdaten aus. Meldungen zu folgenden
Punkten sind besonders willkommen:

- Ein Client bekommt ein Zertifikat, für das er nicht berechtigt ist.
- Bootstrap-Token lassen sich wiederverwenden, erraten oder gelten länger als vorgesehen.
- Ein Agent kann auf dem Vermittler mehr lesen oder schreiben als seine eigenen Zertifikate.
- Die Aufzeichnung ist unvollständig oder fälschbar.
<br /><br />
<p align="right"><img src="../docs/flying-certs.png" alt="FlyingCerts" width="60" height="60"></p>
