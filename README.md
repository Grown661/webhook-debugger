# webhook-debugger

Selbst gehosteter Webhook-Empfänger und -Debugger — wie requestbin, aber ohne Cloud und
ohne Abhängigkeiten. Ein Bin erstellen, die Hook-URL in einen Dienst (GitHub, Stripe,
CI, Discord, ...) eintragen und jeden eingehenden Request live im Browser inspizieren.

## Problem

Beim Integrieren von Webhooks sieht man nie, was der fremde Dienst *wirklich* schickt:
Welche Header? Welches Body-Format? Signiert er? Dieser Debugger nimmt **jede** Methode
an, speichert Methode, Header, Query, Roh-Body, Zeitstempel und Absender-IP und zeigt
alles aufklappbar im Web-UI — aktualisiert alle 2 Sekunden.

Optional leitet ein Bin jeden Request an eine `forwardUrl` weiter (Proxy-Modus): so kann
man den echten Empfänger weiterlaufen lassen und trotzdem mitschneiden.

## Features

- **Alles-Empfänger**: `POST/GET/PUT/PATCH/DELETE/...` an `/hook/:binId` wird angenommen und gespeichert
- **Web-UI**: Bin per Klick erstellen, Requests live verfolgen (2s-Polling), Details aufklappbar
- **Ringpuffer**: die letzten 50 Requests pro Bin, ältere fallen raus
- **Weiterleitung**: optionale `forwardUrl` pro Bin — Requests werden durchgereicht, Ergebnis (Status/Fehler) wird am Eintrag notiert
- **Bin-URL teilbar**: `#binId` im URL-Hash, das UI stellt das Bin beim Öffnen wieder her
- **Body-Limit**: 256 KB pro Request (größere Bodies werden gekürzt markiert, der Webhook bekommt trotzdem 200)
- **JSON-Persistenz**: Bins überleben einen Neustart

## Stack

- Node.js (>= 18), **nur Builtins**: `node:http`, `node:https`, `node:crypto`, `node:fs`
- Frontend: eine statische `public/index.html`, Vanilla JS
- Persistenz: `data/bins.json`

## Setup & Start

```bash
node server.js
# webhook-debugger laeuft auf http://localhost:8216
```

Dann im Browser `http://localhost:8216` öffnen, Bin erstellen und testen:

```bash
curl -X POST http://localhost:8216/hook/<binId> \
  -H "Content-Type: application/json" \
  -H "X-Signature: test123" \
  -d '{"event":"push","repo":"demo"}'
```

Anderer Port: `PORT=8300 node server.js`

## SSRF-Schutz fuer Forwards (opt-in)

Standardmaessig darf `forwardUrl` auf beliebige Ziele zeigen — inklusive
`localhost` und LAN-IPs, weil das bei einem lokalen Debug-Tool oft genau
gewollt ist (z. B. Forward an den eigenen Dev-Server).

Wird der Debugger aber erreichbar betrieben (LAN/Internet), sollte der
Schutz aktiviert werden:

```bash
SSRF_PROTECT=1 node server.js
```

Damit prueft `assertPublicUrl()` jede Forward-URL vor dem Request:
nur `http/https`, Hostname wird per DNS aufgeloest, und private/reservierte
Ziele (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
169.254.0.0/16, 0.0.0.0/8, `::1`, fc00::/7, fe80::/10, `localhost`) werden
geblockt. Geblockte Forwards erscheinen am gespeicherten Request als
`forward.error` ("SSRF-Schutz: ..."); das Capture selbst ist nie betroffen.

## API

| Methode | Pfad | Beschreibung |
|---|---|---|
| ANY | `/hook/:binId` | Webhook-Empfang — speichert den kompletten Request |
| POST | `/api/bins` | Bin erstellen (`{"forwardUrl": "..."}` optional) |
| GET | `/api/bins/:binId` | Bin-Metadaten |
| GET | `/api/bins/:binId/requests` | Gespeicherte Requests, neueste zuerst (`?limit=`) |
| PUT | `/api/bins/:binId` | `forwardUrl` setzen/entfernen |
| DELETE | `/api/bins/:binId` | Bin löschen |
| GET | `/` | Web-UI |

## Screenshot

_(Screenshot folgt)_

## Lizenz

MIT
