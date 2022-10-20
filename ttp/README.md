# SRAT TTP Server

## Server starten
```
./gradlew srat-ttp:run --args="-d src/dist/ttp.sqlite -p <port> [--noTLS]"
```
Standardmäßig wird der Server auf Port 5001 gestartet und verwendet TLS.
Wenn der angegebene Pfad zur Datenbank nicht existiert, so wird eine neue Datenbank-Datei mit leeren Tabellen erzeugt.
Diese können dann z.B. mit DBBrowser gefüllt werden.

## Release erstellen
```
./gradlew srat-ttp:installDist
```
Die ZIP-Datei wird im Verzeichnis _build/distributions/_ erstellt.