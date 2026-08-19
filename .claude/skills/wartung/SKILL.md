---
description: Prüft ein Projekt auf Wartungsrückstand — wirkungslose ENV-Variablen, abgekündigte Modelle und APIs, veraltete Laufzeit, Dependency-Advisories, Fehler die sich als Erfolg tarnen, tote Pfade. Nutze dies, wenn der Nutzer nach Updates, Wartung, Aktualität oder Rückstand fragt, oder ein Projekt nach längerer Pause wieder anfasst.
---

# Wartungs-Update

Prüfe in dieser Reihenfolge. Sie ist nach Schadenspotenzial sortiert, nicht
nach Aufwand. Berichte erst, ändere dann.

Verifiziere jede Annahme am Code. Rate nicht. Wenn du eine Quelle nicht
erreichst, schreib das hin, statt aus dem Gedächtnis zu antworten.

## 1. ENV-Vertrag

Stelle zwei Listen gegenüber:

- Alle Variablen, die der Code liest (`grep` auf `process.env` / `os.environ`)
- Alle Variablen, die in der Deploy-Umgebung gesetzt sind

Melde jede Abweichung:

- **Gesetzt, aber nie gelesen** — wirkungslose Konfiguration
- **Gelesen, aber nicht gesetzt** — läuft still auf dem Default
- **Namen, die sich nur in der Schreibweise unterscheiden**

Diese Fehler melden sich nie von selbst. Sie sehen aus wie Konfiguration
und sind keine. Frag den Nutzer nach einem Screenshot der Deploy-Variablen,
falls du sie nicht auslesen kannst.

## 2. Abhängigkeiten mit Verfallsdatum

Suche hartcodierte Modell-IDs, API-Versionen und Endpunkte: `gpt-…`,
`claude-…`, `gemini-…`, `/v1/…`, Datums-Suffixe.

Prüfe jede gegen die offizielle Anbieter-Doku:

- Noch verfügbar?
- Abkündigungs- oder Abschaltdatum?
- Benannter Nachfolger?

Nenne Quelle und Datum. Mach die IDs per ENV konfigurierbar, falls noch
nicht geschehen.

## 3. Laufzeit

Welche Version läuft **tatsächlich** in der Deploy-Umgebung? Nicht was in
der Config steht, sondern was das Deployment meldet.

Ist sie noch im Support? Setzt die Config eine Untergrenze, die der
Anbieter als Versionswahl interpretiert (`>=18` führt zu Node 18)?

## 4. Dependencies

`npm audit` / `pip-audit` laufen lassen. In-range behebbares beheben.
Major-Sprünge melden statt blind ausführen.

## 5. Fehler, die sich als Erfolg tarnen

Suche gezielt nach Stellen, die einen Fehler in ein scheinbares Ergebnis
verwandeln:

- Fallback-Zweige, die bei jedem Fehler `success: true` liefern
- Abgeschnittene LLM-Antworten: Wird `finish_reason` bzw. `stop_reason`
  überhaupt geprüft?
- `JSON.parse` ohne eigenen try/catch innerhalb eines catch
- Platzhalter-Ergebnisse, die als HTTP 200 rausgehen

Melde je Fund: Was sieht der Nutzer, und was passiert wirklich?

## 6. Tote Pfade

Code, Dateien und Zweige ohne Referenz. Besonders **Fallback- und
Redundanz-Pfade**: Die laufen im Normalbetrieb nie und brechen deshalb
unbemerkt.

## Output

Report nach Schweregrad (Hoch/Mittel/Niedrig). Pro Fund: Datei, Zeile,
ein Satz zum konkreten Fehlerszenario — kein „könnte problematisch sein".
Danach ein priorisierter Umsetzungsvorschlag in nachvollziehbaren Schritten.

## Was du direkt umsetzen darfst

Eindeutige, risikoarme Korrekturen: fehlende Fehlerprüfungen, ungesicherte
Parser, in-range Dependency-Fixes, Laufzeit-Untergrenze anheben.

Auf neuem Branch committen, Draft-PR öffnen, **nicht mergen**.

## Was du vorher vorlegen musst

Alles, was das Verhalten in Produktion ändert: Modellwechsel, geänderte
Statuscodes, Löschen von Dateien, Architekturentscheidungen.

## Testen

Verifiziere jede Änderung, bevor du sie meldest. Wo kein Test existiert,
starte den Dienst gegen einen Mock und provoziere den Fehlerfall aktiv.
Schreib in den PR, was du wie geprüft hast.

## Zum Schluss

Aktualisiere den Steckbrief in `CLAUDE.md`: Laufzeit-Version,
Modell-IDs, Enddaten, ENV-Liste, Datum des Durchgangs.
