---
id: T-2
type: Task
title: "Ratenbegrenzung erst nach der Identitaetspruefung, nie auf ungepruefte Eingaben"
status: offen
milestone: M-2
tags: [sicherheit, test]
created: 2026-09-19
---

CertMate bildete den Zaehler-Schluessel der Ratenbegrenzung aus dem **Hash des uebergebenen
Tokens — vor dessen Pruefung** ([#420](https://github.com/fabriziosalmi/certmate/issues/420)).
Damit erzeugt jeder zufaellige Token einen eigenen Zaehler: die Begrenzung greift nie, und der
Zaehlerspeicher selbst wird zum Angriffsziel.

**Zu tun:** Zaehler werden an die **geprueften** Identitaeten gebunden (Agent aus dem
Client-Zertifikat) oder, wo es noch keine gibt (Bootstrap), an die Gegenstelle der Verbindung —
niemals an einen Wert, den der Aufrufer frei waehlt. Der Speicher ist nach oben begrenzt.

**Fertig, wenn:** Ein Test schickt viele Anfragen mit jeweils neuem, ungueltigem Token und weist
nach, dass die Begrenzung greift und der Speicher nicht mitwaechst.
