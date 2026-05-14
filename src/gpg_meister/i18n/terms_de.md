# GPG Meister — Deutsches Terminologie-Glossar

Diese Datei definiert die verbindlichen deutschen Begriffe für die Benutzeroberfläche
und Dokumentation von GPG Meister. Übersetzer müssen diese Begriffe exakt verwenden.

## Kryptografische Begriffe

| Begriff | Definition |
|---|---|
| **Schlüssel** | Ein kryptografischer Schlüssel zum Verschlüsseln, Entschlüsseln, Signieren oder Verifizieren von Daten. |
| **Öffentlicher Schlüssel** | Der teilbare Teil eines Schlüsselpaares. Jeder kann ihn verwenden, um Nachrichten an dich zu verschlüsseln oder deine Signaturen zu überprüfen. |
| **Privater Schlüssel** | Der geheime Teil eines Schlüsselpaares. Bewahre ihn sicher auf – jeder mit Zugriff darauf kann deine Nachrichten entschlüsseln und sich als du ausgeben. |
| **Schlüsselpaar** | Ein aufeinander abgestimmtes Paar aus öffentlichem und privatem Schlüssel. |
| **Fingerabdruck** | Die vollständige, eindeutige 40-stellige hexadezimale Kennung eines GPG-Schlüssels. Dies ist der **einzige sichere Weg**, einen Schlüssel zu identifizieren. Überprüfe Fingerabdrücke immer über einen separaten Kanal, bevor du einem Schlüssel vertraust. |
| **Schlüssel-ID** | Ein kürzeres Suffix eines Fingerabdrucks (normalerweise 8 oder 16 Zeichen). Schlüssel-IDs sind **nicht eindeutig** und können leicht gefälscht werden; GPG Meister zeigt sie zur Übersicht an, verlässt sich für Sicherheitsoperationen jedoch immer auf Fingerabdrücke. |
| **Signatur** | Ein kryptografischer Beweis, dass eine Nachricht vom Inhaber eines bestimmten privaten Schlüssels erstellt wurde und seitdem nicht verändert wurde. |
| **Vertrauen** | Deine lokale Einschätzung, ob ein Schlüssel tatsächlich der genannten Person gehört. GPG Meister vertraut Schlüsseln nie automatisch – du musst sie selbst verifizieren. |
| **Widerruf** | Das dauerhafte Ungültigmachen eines Schlüssels, um anzuzeigen, dass er nicht mehr verwendet werden soll (z. B. weil der private Schlüssel kompromittiert wurde). |
| **Passphrase** | Ein Passwort zum Schutz eines privaten Schlüssels oder Tresors. Verwende eine lange Passphrase – eine Folge von vier oder mehr unzusammenhängenden Wörtern ist ideal. |
| **KDF / Argon2id** | Schlüsselableitungsfunktion. Wandelt eine Passphrase in einen kryptografischen Schlüssel um. Argon2id ist der empfohlene Algorithmus (RFC 9106) – er ist absichtlich langsam und speicherintensiv, um Brute-Force-Angriffe zu erschweren. |
| **AEAD / ChaCha20-Poly1305** | Authentifizierte Verschlüsselung mit zugehörigen Daten. Ein Verschlüsselungsalgorithmus, der gleichzeitig Vertraulichkeit, Integrität und Authentizität gewährleistet. ChaCha20-Poly1305 ist der Standard-Tresor-Algorithmus. |

## Anwendungsspezifische Begriffe

| Begriff | Definition |
|---|---|
| **Tresor** | Eine verschlüsselte Backup-Datei mit einem oder mehreren GPG-Schlüsselpaaren. Dient zur Übertragung von Schlüsseln zwischen Geräten oder zur Offline-Sicherung. |
| **Tresor-Hauptpassphrase** | Die Passphrase, die eine Tresor-Datei schützt. Verschieden von (und sollte nicht identisch sein mit) der GPG-Schlüssel-Passphrase. |
| **Schlüsselbund** | Die lokale Sammlung von GPG-Schlüsseln, die von dieser Anwendung verwaltet wird. Gespeichert im dedizierten GnuPG-Home-Verzeichnis der Anwendung. |
