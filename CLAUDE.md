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
| Tests | `npm test` (node:test, keine zusätzliche Abhängigkeit) |

## Abhängigkeiten mit Enddatum

Stand: 19.08.2026

| Was | Wert | Endet | Quelle |
|---|---|---|---|
| OpenAI-Modell (beide Stufen) | `gpt-4.1-mini` | **ungeprüft, siehe unten** | — |
| Anthropic-Fallback | `claude-haiku-4-5` | frühestens 15.10.2026 | Anbieter-Doku, 19.08.2026 |
| LanguageTool | `api.languagetool.org` | kein Datum | — |
| Node | 22 | ca. April 2027 | — |

Der Anthropic-Wert ist am 19.08.2026 gegen die Abkündigungsseite von
Anthropic geprüft: `claude-haiku-4-5-20251001` steht auf **Active**,
Ruhestand „not sooner than October 15, 2026". Der Code nutzt den Alias
`claude-haiku-4-5`; das Datum hängt an der datierten ID.

**Offen: OpenAI-Abschaltdatum.** Alle OpenAI-Domains sind aus der
Wartungsumgebung durch die Egress-Policy gesperrt
(`platform.openai.com`, `developers.openai.com`, `openai.com`,
`community.openai.com` — alle `EGRESS_BLOCKED`). Die Primärquelle war
nicht erreichbar, das Datum ist deshalb **nicht bestätigt**. Eine
Web-Suche am 19.08.2026 nannte für `gpt-4.1-mini` einen API-Stichtag
14.10.2026 und eine ChatGPT-Abschaltung am 13.02.2026 — beides aus
Drittquellen, die sich widersprechen. Vor dem nächsten Durchgang von Hand
auf der OpenAI-Abkündigungsseite nachsehen. Trifft der Stichtag zu,
betrifft er **beide** Modellstufen zugleich, weil beide Defaults auf
dasselbe Modell zeigen.

Nicht verwenden: `gpt-5-mini` und `gpt-5-nano` (Abschaltung 11.12.2026).
Reasoning-Modelle brauchen `max_completion_tokens` statt `max_tokens` und
eine Code-Änderung.

Anthropic hat `temperature`, `top_p` und `top_k` ab Claude Opus 4.7
abgekündigt: Ein abweichender Wert liefert dort 400. Der Fallback-Pfad
sendet keinen dieser Parameter, ein neueres Modell in `ANTHROPIC_MODEL`
ist also unkritisch.

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
LANGUAGETOOL_API_URL    Endpunkt der Rechtschreibprüfung,
                        Standard https://api.languagetool.org/v2/check
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
- `LanguageTool error:` / `LanguageTool rate limit reached` — die
  regelbasierte Vorprüfung lief nicht. Auf Stufe L0 heißt das: der Text
  wurde gar nicht geprüft.

## Ausfall erkennen, nicht raten

Fällt eine Analysestufe aus, liefern die Endpunkte weiter HTTP 200. Ohne
Kennzeichen sieht das aus wie ein unauffälliger Text. Diese Felder trennen
beides:

| Endpunkt | Feld | Bedeutung bei `true` |
|---|---|---|
| `/api/v2/analyze` | `meta.semanticAnalysisFailed` | nur Regex-Muster gelaufen |
| `/api/v2/analyze/predictive` | `meta.semanticAnalysisFailed` | Prognosewerte beruhen nur auf Regex |
| `/api/v2/analyze/batch` | `semanticAnalysisFailures` (Anzahl), je Text `semanticAnalysisFailed` | betroffene Texte |
| `/api/v2/rewrite` | `truncated` | Ergebnis am Token-Limit abgeschnitten |
| `/api/v2/text-correct` | `meta.languageToolAvailable` | bei `false`: keine Vorprüfung |

`meta.semanticAnalysis` bleibt unverändert und meldet weiter nur, ob die
Stufe etwas gefunden hat. Für die Frage, ob sie überhaupt lief, ist
`semanticAnalysisFailed` zuständig.

Die Regex-Muster erkennen IBAN, E-Mail und Ähnliches. Gesundheit, Kinder,
Emotionen, Arbeitgeber, Urlaub und Rechtliches erkennt **nur** die
semantische Stufe. Fällt sie aus, fehlen genau diese Kategorien.

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
  (Aus diesem Repo nicht nachprüfbar — das Frontend liegt getrennt.)
- Zwei Funktionen werden nirgends aufgerufen: `generateSummary`
  (`server.js:6331`, abgelöst durch `getLocalizedSummary`) und
  `formatBreachNotification` (`server.js:3766`, es gibt keinen Versand).
  Stehen gelassen, nicht gelöscht.
- `/api/v2/text-correct` hängt auf Stufe L0 allein am öffentlichen
  LanguageTool-Dienst. Der begrenzt pro IP, und alle Nutzer teilen sich
  die IP der einen Replica. `LANGUAGETOOL_API_URL` zeigt notfalls auf
  eine eigene Instanz.
- Die Version steht dreimal fest im Code (`server.js:6042`, `:7076`,
  `:7313`) statt aus `package.json` zu kommen. Bei einer
  Versionserhöhung alle drei mit anpassen.

## Offene Major-Sprünge

Bewusst nicht gemacht, jeder braucht einen eigenen Durchgang:
`express` 4 → 5, `openai` 4 → 7, `dotenv` 16 → 17.

## Wartung

`/wartung` startet den Prüflauf (siehe `.claude/skills/wartung/`).
Nach jedem Durchgang die Tabellen oben aktualisieren.

Vorletzter Durchgang: 19.08.2026. Ergebnis: `npm audit` sauber, ENV-Vertrag
stimmt, alle Modell-IDs sind konfigurierbar. Geändert wurden die
Laufzeit-Selbstauskunft und zwei In-range-Updates.

Letzter Durchgang: 19.08.2026 (zweiter Lauf am selben Tag). Schwerpunkt:
Fehler, die sich als Erfolg tarnen. Gefunden und behoben wurden fünf
Stellen, an denen ein Ausfall wie ein unauffälliges Ergebnis aussah —
siehe „Ausfall erkennen, nicht raten". Alle Korrekturen sind additiv:
keine geänderten Statuscodes, keine entfernten oder umgedeuteten Felder.
Dazu kam die erste Testsuite (`npm test`, zehn Tests), jeder neue Wächter
per Mutationsprobe geprüft.

Offen und nur gemeldet, nicht umgesetzt:

- OpenAI-Abschaltdatum unbestätigt (Egress-Sperre, siehe oben).
- Ob die Endpunkte bei einem Ausfall statt HTTP 200 einen 502 liefern
  sollen. `/analyze`, `/api/v2/text-correct` und `/api/v2/text-improve`
  tun das bereits, die drei Analyse-Endpunkte und `/api/v2/rewrite`
  nicht. Das ist eine Produktentscheidung, kein Wartungsfall.
- `meta.provider` bei `/api/v2/text-correct` sagt weiter
  `'languagetool+ai'`, auch wenn LanguageTool ausfiel. Bewusst nicht
  geändert, weil das Frontend den Wert auswerten kann.
- `npm audit` sauber (0 Befunde, 105 Prod-Pakete).
