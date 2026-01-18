/**
 * achtung.live Backend API
 * Datenschutz-Textanalyse mit OpenAI GPT
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const OpenAI = require('openai');

const app = express();
const PORT = process.env.PORT || 3000;

// OpenAI Client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Middleware
app.use(cors({
  origin: ['https://achtung.live', 'http://localhost:3000', 'http://localhost:8888'],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json());

// Analyse-Prompt für GPT
const ANALYZE_SYSTEM_PROMPT = `Du bist ein Datenschutz-Experte und analysierst Texte auf sensible Informationen.

Prüfe den Text auf folgende Kategorien:
- Persönliche Daten (Name, Geburtsdatum, Adresse)
- Finanzdaten (IBAN, Kreditkartennummer, Kontonummer)
- Gesundheitsdaten (Diagnosen, Medikamente, Arztbesuche)
- Standortdaten (Wohnort, Arbeitsplatz, Reisepläne)
- Berufliche Daten (Arbeitgeber, Kollegen, Chef)
- Passwörter oder Zugangsdaten
- Screenshots oder Dokumente mit sensiblen Inhalten

Antworte IMMER im folgenden JSON-Format:
{
  "feedback": ["Liste der erkannten Probleme als Array von Strings"],
  "detected_data": "Komma-separierte Liste der Datenarten",
  "risk_level": "Niedrig/Mittel/Hoch/Kritisch",
  "explanation": "Kurze Erklärung warum diese Daten problematisch sind",
  "tip": "Konkreter Tipp zum sicheren Umgang",
  "rewrite_offer": true/false
}

Wenn keine sensiblen Daten gefunden werden, gib ein leeres feedback-Array zurück.
Sei freundlich aber bestimmt in deinen Hinweisen.`;

// ===========================================
// API v2 - Visual Risk Dashboard
// ===========================================

// Regex patterns for rule-based detection
const PATTERNS = {
  iban: {
    regex: /[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}/g,
    severity: 'critical',
    message: 'IBAN erkannt - niemals in Chats teilen',
    suggestion: 'Bankdaten über sicheren Kanal senden'
  },
  credit_card: {
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    severity: 'critical',
    message: 'Kreditkartennummer erkannt - hohes Betrugsrisiko',
    suggestion: 'Niemals Kartendaten in Nachrichten teilen'
  },
  phone: {
    regex: /(?:\+|00)[1-9][0-9]{1,3}[-\s]?[0-9]{2,4}[-\s]?[0-9]{4,10}|\b0[1-9][0-9]{1,4}[-\s]?[0-9]{4,10}\b/g,
    severity: 'high',
    message: 'Telefonnummer erkannt - kann für Spam/Betrug missbraucht werden',
    suggestion: 'Telefonnummer nur über sichere Kanäle teilen'
  },
  email: {
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    severity: 'medium',
    message: 'E-Mail-Adresse erkannt - Spam- und Phishing-Risiko',
    suggestion: 'E-Mail nur mit vertrauenswürdigen Kontakten teilen'
  },
  password: {
    regex: /(?:passwort|password|pw|kennwort|pin|geheimzahl)\s*[:=]?\s*[^\s,;]{3,}/gi,
    severity: 'critical',
    message: 'Mögliches Passwort erkannt - niemals Passwörter teilen!',
    suggestion: 'Nutze einen Passwort-Manager statt Passwörter zu versenden'
  }
};

// Context-specific warnings
const CONTEXT_WARNINGS = {
  whatsapp: 'WhatsApp-Nachrichten können weitergeleitet werden',
  email: 'E-Mails können unverschlüsselt übertragen werden',
  social: 'Social Media Posts können öffentlich sichtbar sein',
  work: 'Arbeitsnachrichten können vom Arbeitgeber eingesehen werden',
  dating: 'Dating-Apps sind häufig Ziel von Betrügern',
  forum: 'Forenbeiträge sind oft öffentlich und durchsuchbar',
  default: 'Achte darauf, wer diese Nachricht lesen könnte'
};

// Luhn algorithm for credit card validation
function luhnCheck(num) {
  const arr = (num + '')
    .split('')
    .reverse()
    .map(x => parseInt(x));
  const sum = arr.reduce((acc, val, i) => {
    if (i % 2 !== 0) {
      val = val * 2;
      if (val > 9) val = val - 9;
    }
    return acc + val;
  }, 0);
  return sum % 10 === 0;
}

// GPT prompt for semantic analysis (API v2)
const ANALYZE_V2_SYSTEM_PROMPT = `Du bist ein Datenschutz-Experte. Analysiere den Text auf sensible Daten.
Du sollst NUR semantische Kategorien erkennen, die nicht durch einfache Muster erkennbar sind.

Suche nach folgenden Kategorien:
- health: Diagnosen, Medikamente, Krankheiten, Arztbesuche, psychische Probleme
- child: Kindernamen mit Alter, Schulen, Kindergärten, Aktivitäten von Minderjährigen
- location: "bin gerade bei", aktuelle Standorte, GPS-Koordinaten, Adressen
- emotion: Wut, Drohungen, starke negative Emotionen, Beleidigungen
- employer: Firmenname mit Kritik, Beschwerden über Arbeitgeber, interne Informationen
- vacation: Urlaubspläne, "bin nicht zuhause", Abwesenheitszeiten
- legal: Beleidigungen, Verleumdung, rechtlich problematische Aussagen

WICHTIG: Gib für jede Erkennung die EXAKTE Startposition (start) und Endposition (end) im Text an.
Die Position ist 0-basiert (erstes Zeichen = Position 0).

Antworte NUR mit validem JSON:
{
  "findings": [
    {
      "type": "kategorie",
      "match": "der exakte gefundene Text",
      "start": Startposition_als_Zahl,
      "end": Endposition_als_Zahl,
      "severity": "critical|high|medium",
      "message": "Kurze Erklärung auf Deutsch",
      "suggestion": "Verbesserungsvorschlag auf Deutsch"
    }
  ],
  "rewriteSuggestion": "Komplett umgeschriebener sicherer Text (optional, nur wenn sinnvoll)"
}

Severity-Regeln:
- critical: health, child (Kinderdaten)
- high: location, legal
- medium: emotion, employer, vacation

Wenn nichts gefunden wird, gib {"findings": [], "rewriteSuggestion": null} zurück.`;

// Rewrite-Prompt
const REWRITE_SYSTEM_PROMPT = `Du bist ein Datenschutz-Experte.
Schreibe den gegebenen Text so um, dass keine sensiblen persönlichen Daten mehr enthalten sind.
Erhalte den Sinn und Ton des Textes, aber entferne oder anonymisiere:
- Namen, Geburtsdaten, Adressen
- Finanzdaten
- Gesundheitsinformationen
- Standortdetails
- Arbeitgeber-/Kollegennamen

Antworte NUR mit dem umgeschriebenen Text, ohne Erklärungen.`;

// Health Check
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'achtung.live API',
    version: '2.0.0',
    endpoints: {
      v1: ['/analyze', '/rewrite', '/howto'],
      v2: ['/api/v2/analyze']
    }
  });
});

// Analyse-Endpunkt
app.post('/analyze', async (req, res) => {
  try {
    const { text } = req.body;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({
        error: 'Kein Text zum Analysieren angegeben'
      });
    }

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: ANALYZE_SYSTEM_PROMPT },
        { role: 'user', content: text }
      ],
      temperature: 0.3,
      max_tokens: 1000
    });

    const responseText = completion.choices[0].message.content;

    // JSON aus der Antwort extrahieren
    let result;
    try {
      result = JSON.parse(responseText);
    } catch {
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        result = JSON.parse(jsonMatch[0]);
      } else {
        result = {
          feedback: ['Der Text wurde analysiert, aber das Ergebnis konnte nicht verarbeitet werden.'],
          detected_data: 'Unbekannt',
          risk_level: 'Unbekannt',
          explanation: responseText,
          tip: 'Bitte versuche es erneut.',
          rewrite_offer: false
        };
      }
    }

    res.json(result);

  } catch (error) {
    console.error('Analyse-Fehler:', error);
    res.status(500).json({
      error: 'Analyse fehlgeschlagen',
      details: error.message
    });
  }
});

// Rewrite-Endpunkt
app.post('/rewrite', async (req, res) => {
  try {
    const { text } = req.body;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({
        error: 'Kein Text zum Umschreiben angegeben'
      });
    }

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: REWRITE_SYSTEM_PROMPT },
        { role: 'user', content: text }
      ],
      temperature: 0.5,
      max_tokens: 1000
    });

    const rewritten = completion.choices[0].message.content;
    res.json({ rewritten });

  } catch (error) {
    console.error('Rewrite-Fehler:', error);
    res.status(500).json({
      error: 'Umschreiben fehlgeschlagen',
      details: error.message
    });
  }
});

// Howto-Endpunkt
app.get('/howto', (req, res) => {
  res.json({
    howto: `So schützt du deine Daten richtig:

1. IBAN & Kreditkarten
   → Niemals in Chats oder E-Mails teilen
   → Nutze sichere Banking-Apps oder verschlüsselte Dienste

2. Passwörter
   → Nie im Klartext versenden
   → Nutze einen Passwort-Manager

3. Standort & Urlaub
   → Keine Live-Standorte posten
   → Urlaubsfotos erst nach der Rückkehr teilen

4. Gesundheitsdaten
   → Nur über sichere Patientenportale
   → Screenshots von Befunden vermeiden

5. Über Chef & Arbeit
   → Keine Namen nennen
   → Sachlich bleiben, Emotionen rauslassen

6. Screenshots
   → Vorher Namen/Daten schwärzen
   → Metadaten entfernen`
  });
});

// ===========================================
// API v2 - /api/v2/analyze Endpoint
// ===========================================

// Helper: Detect patterns using regex
function detectPatterns(text) {
  const findings = [];

  for (const [type, config] of Object.entries(PATTERNS)) {
    // Reset regex lastIndex for global patterns
    config.regex.lastIndex = 0;
    let match;

    while ((match = config.regex.exec(text)) !== null) {
      // Special validation for credit cards (Luhn check)
      if (type === 'credit_card') {
        const digits = match[0].replace(/\D/g, '');
        if (!luhnCheck(digits) || digits.length < 13 || digits.length > 19) {
          continue;
        }
      }

      findings.push({
        type,
        severity: config.severity,
        match: match[0],
        position: {
          start: match.index,
          end: match.index + match[0].length
        },
        message: config.message,
        suggestion: config.suggestion
      });
    }
  }

  return findings;
}

// Helper: Calculate risk score
function calculateRiskScore(categories) {
  let score = 100;

  for (const cat of categories) {
    if (cat.severity === 'critical') score -= 35;
    else if (cat.severity === 'high') score -= 20;
    else if (cat.severity === 'medium') score -= 10;
  }

  return Math.max(0, score);
}

// Helper: Determine risk level from score
function getRiskLevel(score) {
  if (score >= 80) return 'safe';
  if (score >= 50) return 'warning';
  return 'danger';
}

// Helper: Generate summary
function generateSummary(categories) {
  if (categories.length === 0) {
    return 'Keine Risiken erkannt';
  }

  const critical = categories.filter(c => c.severity === 'critical').length;
  const high = categories.filter(c => c.severity === 'high').length;
  const medium = categories.filter(c => c.severity === 'medium').length;

  const parts = [];
  if (critical > 0) parts.push(`${critical} kritisches${critical > 1 ? '' : ''} Risiko${critical > 1 ? 'en' : ''}`);
  if (high > 0) parts.push(`${high} hohes${high > 1 ? '' : ''} Risiko${high > 1 ? 'en' : ''}`);
  if (medium > 0) parts.push(`${medium} mittleres${medium > 1 ? '' : ''} Risiko${medium > 1 ? 'en' : ''}`);

  return parts.join(' und ') + ' erkannt';
}

// API v2: Analyze endpoint
app.post('/api/v2/analyze', async (req, res) => {
  try {
    const { text, context = 'default', options = {} } = req.body;
    const includeRewrite = options.includeRewrite === true;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({
        error: 'Kein Text zum Analysieren angegeben'
      });
    }

    // Step 1: Pattern-based detection
    const patternFindings = detectPatterns(text);

    // Step 2: GPT-based semantic analysis
    let gptFindings = [];
    let rewriteSuggestion = null;

    try {
      const userPrompt = `Kontext: ${context}\nText: "${text}"`;

      const completion = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [
          { role: 'system', content: ANALYZE_V2_SYSTEM_PROMPT },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.3,
        max_tokens: 1500
      });

      const responseText = completion.choices[0].message.content;

      // Parse GPT response
      let gptResult;
      try {
        gptResult = JSON.parse(responseText);
      } catch {
        const jsonMatch = responseText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          gptResult = JSON.parse(jsonMatch[0]);
        }
      }

      if (gptResult && gptResult.findings) {
        // Transform GPT findings to match our format
        gptFindings = gptResult.findings.map(f => ({
          type: f.type,
          severity: f.severity,
          match: f.match,
          position: {
            start: f.start,
            end: f.end
          },
          message: f.message,
          suggestion: f.suggestion
        }));

        rewriteSuggestion = gptResult.rewriteSuggestion;
      }
    } catch (gptError) {
      console.error('GPT-Analyse Fehler:', gptError.message);
      // Continue with pattern-based findings only
    }

    // Step 3: Combine all findings
    const allCategories = [...patternFindings, ...gptFindings];

    // Step 4: Calculate risk score and level
    const riskScore = calculateRiskScore(allCategories);
    const riskLevel = getRiskLevel(riskScore);

    // Step 5: Generate summary
    const summary = generateSummary(allCategories);

    // Step 6: Get context warning
    const contextWarning = CONTEXT_WARNINGS[context.toLowerCase()] || CONTEXT_WARNINGS.default;

    // Step 7: Build response
    const response = {
      riskScore,
      riskLevel,
      summary,
      categories: allCategories,
      contextWarning
    };

    // Step 8: Include rewrite if requested
    if (includeRewrite && allCategories.length > 0) {
      // Use existing rewrite suggestion from GPT or generate new one
      if (rewriteSuggestion) {
        const changes = allCategories.map(cat => {
          const typeLabels = {
            iban: 'IBAN entfernt',
            credit_card: 'Kreditkarte entfernt',
            phone: 'Telefonnummer entfernt',
            email: 'E-Mail entfernt',
            password: 'Passwort entfernt',
            health: 'Gesundheitsdaten entfernt',
            child: 'Kinderdaten entfernt',
            location: 'Standort entfernt',
            emotion: 'Emotion neutralisiert',
            employer: 'Arbeitgeberdaten entfernt',
            vacation: 'Urlaubsinfo entfernt',
            legal: 'Rechtlich problematische Aussage entfernt'
          };
          return typeLabels[cat.type] || `${cat.type} entfernt`;
        });

        // Remove duplicates
        const uniqueChanges = [...new Set(changes)];

        response.rewrite = {
          suggestion: rewriteSuggestion,
          changes: uniqueChanges
        };
      } else {
        // Generate rewrite using dedicated endpoint logic
        try {
          const rewriteCompletion = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [
              { role: 'system', content: REWRITE_SYSTEM_PROMPT },
              { role: 'user', content: text }
            ],
            temperature: 0.5,
            max_tokens: 1000
          });

          const rewrittenText = rewriteCompletion.choices[0].message.content;

          const changes = allCategories.map(cat => {
            const typeLabels = {
              iban: 'IBAN entfernt',
              credit_card: 'Kreditkarte entfernt',
              phone: 'Telefonnummer entfernt',
              email: 'E-Mail entfernt',
              password: 'Passwort entfernt',
              health: 'Gesundheitsdaten entfernt',
              child: 'Kinderdaten entfernt',
              location: 'Standort entfernt',
              emotion: 'Emotion neutralisiert',
              employer: 'Arbeitgeberdaten entfernt',
              vacation: 'Urlaubsinfo entfernt',
              legal: 'Rechtlich problematische Aussage entfernt'
            };
            return typeLabels[cat.type] || `${cat.type} entfernt`;
          });

          const uniqueChanges = [...new Set(changes)];

          response.rewrite = {
            suggestion: rewrittenText,
            changes: uniqueChanges
          };
        } catch (rewriteError) {
          console.error('Rewrite-Fehler:', rewriteError.message);
        }
      }
    }

    res.json(response);

  } catch (error) {
    console.error('API v2 Analyse-Fehler:', error);
    res.status(500).json({
      error: 'Analyse fehlgeschlagen',
      details: error.message
    });
  }
});

// Server starten
app.listen(PORT, () => {
  console.log(`achtung.live API läuft auf Port ${PORT}`);
});
