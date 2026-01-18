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

// Anthropic Client (for fallback)
let anthropic = null;
try {
  if (process.env.ANTHROPIC_API_KEY) {
    const Anthropic = require('@anthropic-ai/sdk');
    anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  }
} catch (e) {
  console.log('Anthropic SDK nicht verfügbar - Fallback deaktiviert');
}

// Provider status tracking
const providerStatus = {
  openai: { available: true, lastError: null, lastCheck: Date.now() },
  anthropic: { available: !!anthropic, lastError: null, lastCheck: Date.now() }
};

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

// Regex patterns for rule-based detection (Extended Phase 2)
const PATTERNS = {
  // === Financial ===
  iban: {
    regex: /[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}/g,
    severity: 'critical',
    category: 'financial',
    message: 'IBAN erkannt - niemals in Chats teilen',
    suggestion: 'Bankdaten über sicheren Kanal senden'
  },
  credit_card: {
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    severity: 'critical',
    category: 'financial',
    message: 'Kreditkartennummer erkannt - hohes Betrugsrisiko',
    suggestion: 'Niemals Kartendaten in Nachrichten teilen',
    validator: 'luhn'
  },
  bic: {
    regex: /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g,
    severity: 'high',
    category: 'financial',
    message: 'BIC/SWIFT-Code erkannt',
    suggestion: 'Bankdaten nur über sichere Kanäle teilen'
  },
  account_number: {
    regex: /(?:Konto(?:nummer)?|Account|Acct)[:\s]*[0-9]{5,12}/gi,
    severity: 'high',
    category: 'financial',
    message: 'Kontonummer erkannt',
    suggestion: 'Kontodaten über sicheren Kanal senden'
  },

  // === Identity Documents ===
  national_id: {
    regex: /(?:Personalausweis|Ausweis(?:nummer)?|ID)[:\s]*[A-Z0-9]{9,12}/gi,
    severity: 'critical',
    category: 'identity',
    message: 'Ausweisnummer erkannt - Identitätsdiebstahl-Risiko',
    suggestion: 'Ausweisdaten niemals digital teilen'
  },
  passport: {
    regex: /(?:Reisepass|Passport)[:\s]*[A-Z0-9]{8,9}/gi,
    severity: 'critical',
    category: 'identity',
    message: 'Reisepassnummer erkannt',
    suggestion: 'Passdaten nur bei behördlichen Anfragen teilen'
  },
  tax_id: {
    regex: /(?:Steuer-?ID|Steueridentifikationsnummer|TIN)[:\s]*[0-9]{10,11}/gi,
    severity: 'critical',
    category: 'identity',
    message: 'Steuer-ID erkannt',
    suggestion: 'Steuer-ID nur mit Finanzamt/Arbeitgeber teilen'
  },
  social_security: {
    regex: /(?:Sozialversicherung(?:snummer)?|SV-?Nummer|SVNR)[:\s]*[0-9]{10,12}/gi,
    severity: 'critical',
    category: 'identity',
    message: 'Sozialversicherungsnummer erkannt',
    suggestion: 'SV-Nummer nur bei offiziellen Anfragen angeben'
  },
  drivers_license: {
    regex: /(?:Führerschein(?:nummer)?|Driver'?s?\s*License)[:\s]*[A-Z0-9]{8,12}/gi,
    severity: 'high',
    category: 'identity',
    message: 'Führerscheinnummer erkannt',
    suggestion: 'Führerscheindaten nicht digital teilen'
  },

  // === Health ===
  health_insurance: {
    regex: /(?:Krankenversicherung(?:snummer)?|Versichertennummer|KVNR)[:\s]*[A-Z][0-9]{9}/gi,
    severity: 'critical',
    category: 'health',
    message: 'Krankenversicherungsnummer erkannt',
    suggestion: 'Versicherungsdaten nur mit medizinischem Personal teilen'
  },
  medical_record: {
    regex: /(?:Patientennummer|Fallnummer|Aktenzeichen)[:\s]*[A-Z0-9]{6,15}/gi,
    severity: 'critical',
    category: 'health',
    message: 'Medizinische Aktennummer erkannt',
    suggestion: 'Patientendaten sind besonders schützenswert'
  },

  // === Digital ===
  ip_address: {
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    severity: 'medium',
    category: 'digital',
    message: 'IP-Adresse erkannt - ermöglicht Standortbestimmung',
    suggestion: 'IP-Adressen können zur Lokalisierung genutzt werden'
  },
  mac_address: {
    regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
    severity: 'medium',
    category: 'digital',
    message: 'MAC-Adresse erkannt',
    suggestion: 'MAC-Adressen identifizieren Geräte eindeutig'
  },
  username: {
    regex: /(?:Username|Benutzername|User|Login)[:\s]*[a-zA-Z0-9_.-]{3,30}/gi,
    severity: 'medium',
    category: 'digital',
    message: 'Benutzername erkannt',
    suggestion: 'Benutzernamen können für Account-Angriffe genutzt werden'
  },
  password: {
    regex: /(?:passwort|password|pw|kennwort|pin|geheimzahl)\s*[:=]?\s*[^\s,;]{3,}/gi,
    severity: 'critical',
    category: 'digital',
    message: 'Mögliches Passwort erkannt - niemals Passwörter teilen!',
    suggestion: 'Nutze einen Passwort-Manager statt Passwörter zu versenden'
  },
  api_key: {
    regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token|bearer)[:\s=]*[a-zA-Z0-9_-]{20,}/gi,
    severity: 'critical',
    category: 'digital',
    message: 'API-Schlüssel erkannt - ermöglicht Systemzugriff',
    suggestion: 'API-Keys sofort rotieren wenn geleakt'
  },

  // === Personal ===
  phone: {
    regex: /(?:\+|00)[1-9][0-9]{1,3}[-\s]?[0-9]{2,4}[-\s]?[0-9]{4,10}|\b0[1-9][0-9]{1,4}[-\s]?[0-9]{4,10}\b/g,
    severity: 'high',
    category: 'personal',
    message: 'Telefonnummer erkannt - kann für Spam/Betrug missbraucht werden',
    suggestion: 'Telefonnummer nur über sichere Kanäle teilen'
  },
  email: {
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    severity: 'medium',
    category: 'personal',
    message: 'E-Mail-Adresse erkannt - Spam- und Phishing-Risiko',
    suggestion: 'E-Mail nur mit vertrauenswürdigen Kontakten teilen'
  },
  date_of_birth: {
    regex: /(?:Geburtsdatum|Geb\.|Geboren|DOB|Birthday)[:\s]*(?:[0-3]?[0-9][./-][0-1]?[0-9][./-](?:19|20)?[0-9]{2})/gi,
    severity: 'high',
    category: 'personal',
    message: 'Geburtsdatum erkannt - wichtiges Identitätsmerkmal',
    suggestion: 'Geburtsdatum kann für Identitätsdiebstahl genutzt werden'
  },
  age: {
    regex: /\b(?:ich bin|er ist|sie ist|bin)\s*([0-9]{1,3})\s*(?:Jahre?|J\.)\s*(?:alt)?\b/gi,
    severity: 'medium',
    category: 'personal',
    message: 'Altersangabe erkannt',
    suggestion: 'Alter kann zur Identifizierung beitragen'
  },

  // === Location ===
  gps_coordinates: {
    regex: /[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)[,\s]+[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)/g,
    severity: 'high',
    category: 'location',
    message: 'GPS-Koordinaten erkannt - exakter Standort',
    suggestion: 'GPS-Koordinaten verraten deinen genauen Standort'
  },
  license_plate: {
    regex: /\b[A-ZÄÖÜ]{1,3}[-\s]?[A-Z]{1,2}[-\s]?[0-9]{1,4}[EH]?\b/g,
    severity: 'high',
    category: 'location',
    message: 'Kfz-Kennzeichen erkannt',
    suggestion: 'Kennzeichen können zur Identifizierung genutzt werden'
  }
};

// Category metadata for /api/v2/categories endpoint
const CATEGORY_GROUPS = {
  financial: {
    name: 'Finanzdaten',
    description: 'Bank- und Zahlungsinformationen',
    types: ['iban', 'credit_card', 'bic', 'account_number']
  },
  identity: {
    name: 'Ausweisdaten',
    description: 'Persönliche Identifikationsdokumente',
    types: ['national_id', 'passport', 'tax_id', 'social_security', 'drivers_license']
  },
  health: {
    name: 'Gesundheitsdaten',
    description: 'Medizinische und Versicherungsdaten',
    types: ['health_insurance', 'medical_record']
  },
  digital: {
    name: 'Digitale Zugangsdaten',
    description: 'Accounts, Passwörter und technische Identifier',
    types: ['ip_address', 'mac_address', 'username', 'password', 'api_key']
  },
  personal: {
    name: 'Persönliche Daten',
    description: 'Kontaktdaten und persönliche Informationen',
    types: ['phone', 'email', 'date_of_birth', 'age']
  },
  location: {
    name: 'Standortdaten',
    description: 'Geografische und Fahrzeuginformationen',
    types: ['gps_coordinates', 'license_plate']
  },
  semantic: {
    name: 'Semantische Erkennung (GPT)',
    description: 'Kontextabhängige Erkennung durch KI',
    types: ['health', 'child', 'location', 'emotion', 'employer', 'vacation', 'legal', 'gender', 'religion', 'political', 'biometric', 'photo']
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
    version: '2.1.0',
    endpoints: {
      v1: ['/analyze', '/rewrite', '/howto'],
      v2: ['/api/v2/analyze', '/api/v2/rewrite', '/api/v2/analyze/batch', '/api/v2/categories', '/api/v2/health']
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

// Helper: Check if a position range overlaps with any existing findings
function overlapsWithExisting(start, end, existingFindings) {
  for (const finding of existingFindings) {
    const fStart = finding.position.start;
    const fEnd = finding.position.end;
    // Check for any overlap
    if (start < fEnd && end > fStart) {
      return true;
    }
  }
  return false;
}

// Helper: Detect patterns using regex
function detectPatterns(text) {
  const findings = [];

  // Define detection order: Critical financial/identity first to prevent false positives
  const detectionOrder = [
    // Financial (highest priority - prevent false positives in IBANs)
    'iban', 'credit_card', 'bic', 'account_number',
    // Identity documents
    'national_id', 'passport', 'tax_id', 'social_security', 'drivers_license',
    // Health
    'health_insurance', 'medical_record',
    // Digital
    'api_key', 'password', 'username', 'ip_address', 'mac_address',
    // Personal
    'phone', 'email', 'date_of_birth', 'age',
    // Location
    'gps_coordinates', 'license_plate'
  ];

  // Types that should not overlap with financial data
  const overlapSensitiveTypes = ['phone', 'email', 'ip_address', 'gps_coordinates'];

  for (const type of detectionOrder) {
    const config = PATTERNS[type];
    if (!config) continue;

    // Reset regex lastIndex for global patterns
    config.regex.lastIndex = 0;
    let match;

    while ((match = config.regex.exec(text)) !== null) {
      const matchStart = match.index;
      const matchEnd = match.index + match[0].length;

      // Special validation for credit cards (Luhn check)
      if (type === 'credit_card' || config.validator === 'luhn') {
        const digits = match[0].replace(/\D/g, '');
        if (!luhnCheck(digits) || digits.length < 13 || digits.length > 19) {
          continue;
        }
      }

      // Skip matches that overlap with already detected patterns (prevent IBAN -> phone false positives)
      if (overlapSensitiveTypes.includes(type) && overlapsWithExisting(matchStart, matchEnd, findings)) {
        continue;
      }

      findings.push({
        type,
        severity: config.severity,
        category: config.category,
        match: match[0],
        position: {
          start: matchStart,
          end: matchEnd
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

// ===========================================
// API v2 - Phase 2 Endpoints
// ===========================================

// Helper: Call AI with provider fallback
async function callAIWithFallback(messages, options = {}) {
  const { temperature = 0.3, max_tokens = 1500 } = options;
  let provider = 'openai';
  let model = 'gpt-4o-mini';

  try {
    // Try OpenAI first
    const completion = await openai.chat.completions.create({
      model,
      messages,
      temperature,
      max_tokens
    });

    providerStatus.openai.available = true;
    providerStatus.openai.lastCheck = Date.now();

    return {
      content: completion.choices[0].message.content,
      provider,
      model
    };
  } catch (openaiError) {
    console.error('OpenAI Fehler:', openaiError.message);
    providerStatus.openai.available = false;
    providerStatus.openai.lastError = openaiError.message;
    providerStatus.openai.lastCheck = Date.now();

    // Fallback to Anthropic if available
    if (anthropic) {
      try {
        provider = 'anthropic';
        model = 'claude-3-haiku-20240307';

        // Convert messages format for Anthropic
        const systemMessage = messages.find(m => m.role === 'system')?.content || '';
        const userMessages = messages.filter(m => m.role !== 'system');

        const response = await anthropic.messages.create({
          model,
          max_tokens,
          system: systemMessage,
          messages: userMessages.map(m => ({
            role: m.role,
            content: m.content
          }))
        });

        providerStatus.anthropic.available = true;
        providerStatus.anthropic.lastCheck = Date.now();

        return {
          content: response.content[0].text,
          provider,
          model
        };
      } catch (anthropicError) {
        console.error('Anthropic Fehler:', anthropicError.message);
        providerStatus.anthropic.available = false;
        providerStatus.anthropic.lastError = anthropicError.message;
        providerStatus.anthropic.lastCheck = Date.now();
      }
    }

    throw new Error('Alle AI-Provider nicht verfügbar');
  }
}

// GET /api/v2/categories - List all detection categories
app.get('/api/v2/categories', (req, res) => {
  const categories = {};

  for (const [groupId, group] of Object.entries(CATEGORY_GROUPS)) {
    categories[groupId] = {
      name: group.name,
      description: group.description,
      types: group.types.map(type => {
        const pattern = PATTERNS[type];
        if (pattern) {
          return {
            type,
            severity: pattern.severity,
            message: pattern.message,
            suggestion: pattern.suggestion,
            detection: 'regex'
          };
        }
        // Semantic types (GPT-detected)
        return {
          type,
          detection: 'semantic',
          description: `Wird durch KI-Analyse erkannt`
        };
      })
    };
  }

  res.json({
    totalPatterns: Object.keys(PATTERNS).length,
    totalGroups: Object.keys(CATEGORY_GROUPS).length,
    categories
  });
});

// GET /api/v2/health - API and provider health status
app.get('/api/v2/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'achtung.live API',
    version: '2.1.0',
    timestamp: new Date().toISOString(),
    providers: {
      openai: {
        available: providerStatus.openai.available,
        lastCheck: new Date(providerStatus.openai.lastCheck).toISOString(),
        lastError: providerStatus.openai.lastError
      },
      anthropic: {
        configured: !!anthropic,
        available: providerStatus.anthropic.available,
        lastCheck: new Date(providerStatus.anthropic.lastCheck).toISOString(),
        lastError: providerStatus.anthropic.lastError
      }
    },
    endpoints: {
      v1: ['/analyze', '/rewrite', '/howto'],
      v2: ['/api/v2/analyze', '/api/v2/rewrite', '/api/v2/analyze/batch', '/api/v2/categories', '/api/v2/health']
    }
  });
});

// Rewrite mode prompts
const REWRITE_MODE_PROMPTS = {
  anonymize: `Du bist ein Datenschutz-Experte.
Schreibe den Text so um, dass alle sensiblen Daten durch generische Platzhalter ersetzt werden.
- Namen → [NAME]
- IBANs → [IBAN]
- Telefonnummern → [TELEFON]
- E-Mail-Adressen → [E-MAIL]
- Adressen → [ADRESSE]
- Gesundheitsdaten → [GESUNDHEIT]
- Etc.

Erhalte den Sinn und die Struktur des Textes.
Antworte mit JSON:
{
  "rewritten": "Der umgeschriebene Text",
  "changes": [
    {"original": "ursprünglicher Text", "replacement": "Ersetzung", "reason": "Begründung"}
  ]
}`,

  redact: `Du bist ein Datenschutz-Experte.
Entferne alle sensiblen Daten aus dem Text und ersetze sie durch [ZENSIERT].
Wenn ein ganzer Satz hauptsächlich aus sensiblen Daten besteht, entferne ihn komplett.

Antworte mit JSON:
{
  "rewritten": "Der zensierte Text",
  "changes": [
    {"original": "ursprünglicher Text", "replacement": "[ZENSIERT]", "reason": "Begründung"}
  ]
}`,

  pseudonymize: `Du bist ein Datenschutz-Experte.
Ersetze alle sensiblen Daten durch realistische aber fiktive Daten:
- Namen → andere Namen (Max Mustermann, Anna Schmidt, etc.)
- IBANs → fiktive IBANs (DE00 0000 0000 0000 0000 00)
- Telefonnummern → fiktive Nummern (+49 123 456789)
- Adressen → fiktive Adressen (Musterstraße 1, 12345 Musterstadt)

Der Text soll lesbar bleiben und den gleichen Stil haben.
Antworte mit JSON:
{
  "rewritten": "Der pseudonymisierte Text",
  "changes": [
    {"original": "ursprünglicher Text", "replacement": "fiktiver Ersatz", "reason": "Begründung"}
  ]
}`
};

// POST /api/v2/rewrite - Smart rewrite with modes
app.post('/api/v2/rewrite', async (req, res) => {
  try {
    const { text, mode = 'anonymize', context = 'default' } = req.body;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({
        error: 'Kein Text zum Umschreiben angegeben'
      });
    }

    const validModes = ['anonymize', 'redact', 'pseudonymize'];
    if (!validModes.includes(mode)) {
      return res.status(400).json({
        error: `Ungültiger Modus. Erlaubt: ${validModes.join(', ')}`
      });
    }

    const systemPrompt = REWRITE_MODE_PROMPTS[mode];
    const userPrompt = `Kontext: ${context}\n\nText:\n${text}`;

    const aiResponse = await callAIWithFallback([
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ], { temperature: 0.5 });

    // Parse response
    let result;
    try {
      result = JSON.parse(aiResponse.content);
    } catch {
      const jsonMatch = aiResponse.content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        result = JSON.parse(jsonMatch[0]);
      } else {
        // Fallback: treat entire response as rewritten text
        result = {
          rewritten: aiResponse.content,
          changes: []
        };
      }
    }

    res.json({
      mode,
      original: text,
      rewritten: result.rewritten,
      changes: result.changes || [],
      meta: {
        provider: aiResponse.provider,
        model: aiResponse.model
      }
    });

  } catch (error) {
    console.error('API v2 Rewrite-Fehler:', error);
    res.status(500).json({
      error: 'Umschreiben fehlgeschlagen',
      details: error.message
    });
  }
});

// POST /api/v2/analyze/batch - Batch analysis with parallel processing
app.post('/api/v2/analyze/batch', async (req, res) => {
  try {
    const { texts, context = 'default', options = {} } = req.body;

    if (!texts || !Array.isArray(texts) || texts.length === 0) {
      return res.status(400).json({
        error: 'Keine Texte zum Analysieren angegeben. Erwartet: { texts: [...] }'
      });
    }

    if (texts.length > 20) {
      return res.status(400).json({
        error: 'Maximal 20 Texte pro Batch erlaubt'
      });
    }

    const maxConcurrent = 10;
    const results = [];
    const startTime = Date.now();

    // Process in batches of maxConcurrent
    for (let i = 0; i < texts.length; i += maxConcurrent) {
      const batch = texts.slice(i, i + maxConcurrent);

      const batchPromises = batch.map(async (text, index) => {
        const actualIndex = i + index;

        if (!text || typeof text !== 'string' || text.trim().length === 0) {
          return {
            index: actualIndex,
            error: 'Leerer oder ungültiger Text',
            riskScore: null,
            riskLevel: null
          };
        }

        try {
          // Pattern-based detection
          const patternFindings = detectPatterns(text);

          // GPT-based semantic analysis
          let gptFindings = [];

          try {
            const userPrompt = `Kontext: ${context}\nText: "${text}"`;

            const aiResponse = await callAIWithFallback([
              { role: 'system', content: ANALYZE_V2_SYSTEM_PROMPT },
              { role: 'user', content: userPrompt }
            ]);

            let gptResult;
            try {
              gptResult = JSON.parse(aiResponse.content);
            } catch {
              const jsonMatch = aiResponse.content.match(/\{[\s\S]*\}/);
              if (jsonMatch) {
                gptResult = JSON.parse(jsonMatch[0]);
              }
            }

            if (gptResult && gptResult.findings) {
              gptFindings = gptResult.findings.map(f => ({
                type: f.type,
                severity: f.severity,
                match: f.match,
                position: { start: f.start, end: f.end },
                message: f.message,
                suggestion: f.suggestion
              }));
            }
          } catch (gptError) {
            console.error(`Batch GPT-Fehler für Text ${actualIndex}:`, gptError.message);
          }

          const allCategories = [...patternFindings, ...gptFindings];
          const riskScore = calculateRiskScore(allCategories);
          const riskLevel = getRiskLevel(riskScore);

          return {
            index: actualIndex,
            text: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
            riskScore,
            riskLevel,
            findingsCount: allCategories.length,
            categories: allCategories
          };
        } catch (itemError) {
          return {
            index: actualIndex,
            error: itemError.message,
            riskScore: null,
            riskLevel: null
          };
        }
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
    }

    // Calculate summary statistics
    const successfulResults = results.filter(r => r.riskScore !== null);
    const avgRiskScore = successfulResults.length > 0
      ? Math.round(successfulResults.reduce((sum, r) => sum + r.riskScore, 0) / successfulResults.length)
      : null;

    const riskDistribution = {
      safe: successfulResults.filter(r => r.riskLevel === 'safe').length,
      warning: successfulResults.filter(r => r.riskLevel === 'warning').length,
      danger: successfulResults.filter(r => r.riskLevel === 'danger').length
    };

    res.json({
      processed: texts.length,
      successful: successfulResults.length,
      failed: results.filter(r => r.error).length,
      processingTime: Date.now() - startTime,
      summary: {
        averageRiskScore: avgRiskScore,
        riskDistribution,
        totalFindings: successfulResults.reduce((sum, r) => sum + r.findingsCount, 0)
      },
      results
    });

  } catch (error) {
    console.error('API v2 Batch-Fehler:', error);
    res.status(500).json({
      error: 'Batch-Analyse fehlgeschlagen',
      details: error.message
    });
  }
});

// Server starten
app.listen(PORT, () => {
  console.log(`achtung.live API läuft auf Port ${PORT}`);
});
