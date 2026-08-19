# achtung-live-backend

Backend-API für achtung.live. Prüft Texte auf sensible Daten, schreibt sie
auf Wunsch um und korrigiert Rechtschreibung und Stil.

Frontend: `achtung-live-frontend` (statisch, Netlify). Es ruft dieses
Backend über Netlify-Functions als Server-zu-Server-Proxy auf.

## Betrieb

| | |
|---|---|
| Stack | Node/Express, eine Datei (`server.js`) |
| Deploy | Railway, EU West, 1 Replica |
| Laufzeit | Node 22.22.2 (aus dem Deploy-Log, 19.08.2026) |
| Datenhaltung | **keine.** Alles in In-Memory-Maps, weg bei jedem Neustart |

## Abhängigkeiten mit Enddatum

Stand: 19.08.2026

| Was | Wert | Endet |
|---|---|---|
| OpenAI-Modell (beide Stufen) | `gpt-4.1-mini` | kein Datum genannt |
| Anthropic-Fallback | `claude-haiku-4-5` | **frühestens 15.10.2026** |
| Node | 22 | ca. April 2027 |

Nicht verwenden: `gpt-5-mini` und `gpt-5-nano` (Abschaltung 11.12.2026).
Reasoning-Modelle brauchen `max_completion_tokens` statt `max_tokens` und
eine Code-Änderung.

## ENV-Variablen

Der Code liest genau diese. Andere Namen bleiben wirkungslos:

```
OPENAI_API_KEY          erforderlich
OPENAI_MODEL            setzt beide Modellstufen
OPENAI_MODEL_FAST       überschreibt nur die schnelle Stufe
OPENAI_MODEL_QUALITY    überschreibt nur die gründliche Stufe
ANTHROPIC_API_KEY       optional, aktiviert den Fallback-Provider
ANTHROPIC_MODEL         Modell des Fallback-Providers
LLM_MAX_TOKENS          Antwort-Budget, Standard 4000
PORT                    Standard 3000
```

Details und geprüfte Alternativen stehen in `.env.example`.

## Zwei Modellstufen

| Stufe | Wann | Endpunkte |
|---|---|---|
| `fast` | Nutzer wartet vor dem Absenden | `/analyze`, `/rewrite`, `/api/v2/analyze`, `/api/v2/rewrite`, `/api/v2/text-correct` |
| `quality` | Auswertung im Hintergrund | `/api/v2/analyze/batch`, `/api/v2/analyze/predictive`, `/api/v2/text-improve` |

## Selbstauskunft im Log

Der Server meldet beim Start seine tatsächlich aktive Konfiguration:

```
achtung.live API läuft auf Port …
Laufzeit: Node …
Modelle: fast=…, quality=…, fallback=…
```

Weicht ein Wert von deiner ENV ab, greift dort der Default — meist ein
Tippfehler im Variablennamen.

Zwei Log-Präfixe im Betrieb beobachten:

- `[MODELL]` — Provider hat ein Modell abgelehnt, der Server ist auf
  `gpt-4o-mini` zurückgeschaltet
- `[TRUNCATED]` — Antwort am Token-Limit abgeschnitten, `LLM_MAX_TOKENS`
  erhöhen

## Bekannte Altlasten

- Kein persistenter Speicher. Alert-Abos, Opt-out-Anfragen und Statistiken
  überleben keinen Neustart.
- Rate-Limiting liegt im Prozessspeicher. Bei mehr als einer Replica
  zählt jede Instanz für sich.
- Der Anthropic-Fallback kennt kein `response_format`. Er nutzt weiter die
  abgesicherte Regex-Auswertung statt Structured Outputs.
- Vier Routen haben im Frontend keinen Proxy und sind von außen nicht
  erreichbar: `/api/v2/breach-scenarios`,
  `/api/v2/footprint/databroker-scan`, `/api/v2/footprint/social-scan`,
  `/api/v2/policy/compare`. Sie laufen, aber niemand ruft sie.

## Offene Major-Sprünge

Bewusst nicht gemacht, jeder braucht einen eigenen Durchgang:
`express` 4 → 5, `openai` 4 → 7, `dotenv` 16 → 17.

## Wartung

`/wartung` startet den Prüflauf (siehe `.claude/skills/wartung/`).
Nach jedem Durchgang die Tabellen oben aktualisieren.

Letzter Durchgang: 19.08.2026. Ergebnis: `npm audit` sauber, ENV-Vertrag
stimmt, alle Modell-IDs sind konfigurierbar. Geändert wurden die
Laufzeit-Selbstauskunft und zwei In-range-Updates.
