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

// Quick Check Cache (in-memory, 5 min TTL)
const quickCheckCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const MAX_CACHE_SIZE = 1000;

// Cache statistics
const cacheStats = {
  hits: 0,
  misses: 0,
  size: 0
};

function getCacheKey(text, context) {
  // Simple hash for cache key
  let hash = 0;
  const str = text + '|' + context;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(36);
}

function getFromCache(key) {
  const entry = quickCheckCache.get(key);
  if (entry && Date.now() - entry.timestamp < CACHE_TTL) {
    cacheStats.hits++;
    return entry.data;
  }
  if (entry) {
    quickCheckCache.delete(key);
    cacheStats.size--;
  }
  cacheStats.misses++;
  return null;
}

function setCache(key, data) {
  // Evict oldest entries if cache is full
  if (quickCheckCache.size >= MAX_CACHE_SIZE) {
    const oldestKey = quickCheckCache.keys().next().value;
    quickCheckCache.delete(oldestKey);
  }
  quickCheckCache.set(key, { data, timestamp: Date.now() });
  cacheStats.size = quickCheckCache.size;
}

// Periodic cache cleanup (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of quickCheckCache.entries()) {
    if (now - entry.timestamp > CACHE_TTL) {
      quickCheckCache.delete(key);
    }
  }
  cacheStats.size = quickCheckCache.size;
}, CACHE_TTL);

// ===========================================
// Multi-Language Support (Phase 4)
// ===========================================

const SUPPORTED_LANGUAGES = ['de', 'en', 'fr', 'es', 'it'];
const DEFAULT_LANGUAGE = 'de';

const LOCALES = {
  de: {
    riskLevels: {
      safe: 'Sicher',
      warning: 'Achtung',
      danger: 'Gefahr'
    },
    summary: {
      noRisks: 'Keine Risiken erkannt',
      risks: '{count} potenzielle Risiken erkannt'
    },
    categories: {
      iban: { message: 'IBAN erkannt - niemals in Chats teilen', suggestion: 'Bankdaten über sicheren Kanal senden' },
      credit_card: { message: 'Kreditkartennummer erkannt - hohes Betrugsrisiko', suggestion: 'Niemals Kartendaten in Nachrichten teilen' },
      bic: { message: 'BIC/SWIFT-Code erkannt', suggestion: 'Bankdaten nur über sichere Kanäle teilen' },
      account_number: { message: 'Kontonummer erkannt', suggestion: 'Kontodaten über sicheren Kanal senden' },
      national_id: { message: 'Ausweisnummer erkannt - Identitätsdiebstahl-Risiko', suggestion: 'Ausweisdaten niemals digital teilen' },
      passport: { message: 'Reisepassnummer erkannt', suggestion: 'Passdaten nur bei behördlichen Anfragen teilen' },
      tax_id: { message: 'Steuer-ID erkannt', suggestion: 'Steuer-ID nur mit Finanzamt/Arbeitgeber teilen' },
      social_security: { message: 'Sozialversicherungsnummer erkannt', suggestion: 'SV-Nummer nur bei offiziellen Anfragen angeben' },
      drivers_license: { message: 'Führerscheinnummer erkannt', suggestion: 'Führerscheindaten nicht digital teilen' },
      health_insurance: { message: 'Krankenversicherungsnummer erkannt', suggestion: 'Versicherungsdaten nur mit medizinischem Personal teilen' },
      medical_record: { message: 'Medizinische Aktennummer erkannt', suggestion: 'Patientendaten sind besonders schützenswert' },
      ip_address: { message: 'IP-Adresse erkannt - ermöglicht Standortbestimmung', suggestion: 'IP-Adressen können zur Lokalisierung genutzt werden' },
      mac_address: { message: 'MAC-Adresse erkannt', suggestion: 'MAC-Adressen identifizieren Geräte eindeutig' },
      username: { message: 'Benutzername erkannt', suggestion: 'Benutzernamen können für Account-Angriffe genutzt werden' },
      password: { message: 'Mögliches Passwort erkannt - niemals Passwörter teilen!', suggestion: 'Nutze einen Passwort-Manager statt Passwörter zu versenden' },
      api_key: { message: 'API-Schlüssel erkannt - ermöglicht Systemzugriff', suggestion: 'API-Keys sofort rotieren wenn geleakt' },
      phone: { message: 'Telefonnummer erkannt - kann für Spam/Betrug missbraucht werden', suggestion: 'Telefonnummer nur über sichere Kanäle teilen' },
      email: { message: 'E-Mail-Adresse erkannt - Spam- und Phishing-Risiko', suggestion: 'E-Mail nur mit vertrauenswürdigen Kontakten teilen' },
      date_of_birth: { message: 'Geburtsdatum erkannt - wichtiges Identitätsmerkmal', suggestion: 'Geburtsdatum kann für Identitätsdiebstahl genutzt werden' },
      age: { message: 'Altersangabe erkannt', suggestion: 'Alter kann zur Identifizierung beitragen' },
      gps_coordinates: { message: 'GPS-Koordinaten erkannt - exakter Standort', suggestion: 'GPS-Koordinaten verraten deinen genauen Standort' },
      license_plate: { message: 'Kfz-Kennzeichen erkannt', suggestion: 'Kennzeichen können zur Identifizierung genutzt werden' },
      address: { message: 'Straßenadresse erkannt', suggestion: 'Adressen können zur Lokalisierung genutzt werden' },
      postal_code: { message: 'Postleitzahl mit Ort erkannt', suggestion: 'PLZ+Ort ermöglicht grobe Standortbestimmung' },
      vacation_hint: { message: 'Abwesenheitshinweis erkannt - Einbrecher könnten dies nutzen', suggestion: 'Abwesenheiten erst nach Rückkehr posten' },
      german_date: { message: 'Datum erkannt', suggestion: 'Daten können zur Identifizierung beitragen' }
    },
    contextWarnings: {
      whatsapp: 'WhatsApp-Nachrichten können weitergeleitet werden',
      email: 'E-Mails können unverschlüsselt übertragen werden',
      social: 'Social Media Posts können öffentlich sichtbar sein',
      work: 'Arbeitsnachrichten können vom Arbeitgeber eingesehen werden',
      dating: 'Dating-Apps sind häufig Ziel von Betrügern',
      forum: 'Forenbeiträge sind oft öffentlich und durchsuchbar',
      default: 'Achte darauf, wer diese Nachricht lesen könnte'
    }
  },
  en: {
    riskLevels: {
      safe: 'Safe',
      warning: 'Warning',
      danger: 'Danger'
    },
    summary: {
      noRisks: 'No risks detected',
      risks: '{count} potential risks detected'
    },
    categories: {
      iban: { message: 'IBAN detected - Never share bank details in chats', suggestion: 'Send bank details via secure channel' },
      credit_card: { message: 'Credit card number detected - High fraud risk', suggestion: 'Never share card details in messages' },
      bic: { message: 'BIC/SWIFT code detected', suggestion: 'Share bank details only via secure channels' },
      account_number: { message: 'Account number detected', suggestion: 'Send account details via secure channel' },
      national_id: { message: 'ID number detected - Identity theft risk', suggestion: 'Never share ID details digitally' },
      passport: { message: 'Passport number detected', suggestion: 'Share passport data only for official requests' },
      tax_id: { message: 'Tax ID detected', suggestion: 'Share tax ID only with authorities/employer' },
      social_security: { message: 'Social security number detected', suggestion: 'Provide SSN only for official requests' },
      drivers_license: { message: 'Driver\'s license number detected', suggestion: 'Don\'t share license details digitally' },
      health_insurance: { message: 'Health insurance number detected', suggestion: 'Share insurance data only with medical staff' },
      medical_record: { message: 'Medical record number detected', suggestion: 'Patient data requires special protection' },
      ip_address: { message: 'IP address detected - Enables location tracking', suggestion: 'IP addresses can be used for localization' },
      mac_address: { message: 'MAC address detected', suggestion: 'MAC addresses uniquely identify devices' },
      username: { message: 'Username detected', suggestion: 'Usernames can be used for account attacks' },
      password: { message: 'Possible password detected - Never share passwords!', suggestion: 'Use a password manager instead of sending passwords' },
      api_key: { message: 'API key detected - Enables system access', suggestion: 'Rotate API keys immediately if leaked' },
      phone: { message: 'Phone number detected - Can be used for spam/fraud', suggestion: 'Share phone numbers only via secure channels' },
      email: { message: 'Email address detected - Spam and phishing risk', suggestion: 'Share email only with trusted contacts' },
      date_of_birth: { message: 'Date of birth detected - Important identity marker', suggestion: 'Birth date can be used for identity theft' },
      age: { message: 'Age information detected', suggestion: 'Age can contribute to identification' },
      gps_coordinates: { message: 'GPS coordinates detected - Exact location', suggestion: 'GPS coordinates reveal your exact location' },
      license_plate: { message: 'License plate detected', suggestion: 'License plates can be used for identification' },
      address: { message: 'Street address detected', suggestion: 'Addresses can be used for localization' },
      postal_code: { message: 'Postal code with city detected', suggestion: 'ZIP+city enables rough location determination' },
      vacation_hint: { message: 'Absence hint detected - Burglars could use this', suggestion: 'Post about absences only after returning' },
      german_date: { message: 'Date detected', suggestion: 'Dates can contribute to identification' }
    },
    contextWarnings: {
      whatsapp: 'WhatsApp messages can be forwarded',
      email: 'Emails can be transmitted unencrypted',
      social: 'Social media posts can be publicly visible',
      work: 'Work messages can be viewed by employer',
      dating: 'Dating apps are often targeted by scammers',
      forum: 'Forum posts are often public and searchable',
      default: 'Consider who might read this message'
    }
  },
  fr: {
    riskLevels: {
      safe: 'Sûr',
      warning: 'Attention',
      danger: 'Danger'
    },
    summary: {
      noRisks: 'Aucun risque détecté',
      risks: '{count} risques potentiels détectés'
    },
    categories: {
      iban: { message: 'IBAN détecté - Ne jamais partager dans les chats', suggestion: 'Envoyer les données bancaires via un canal sécurisé' },
      credit_card: { message: 'Numéro de carte de crédit détecté - Risque de fraude élevé', suggestion: 'Ne jamais partager les données de carte dans les messages' },
      bic: { message: 'Code BIC/SWIFT détecté', suggestion: 'Partager les données bancaires uniquement via des canaux sécurisés' },
      phone: { message: 'Numéro de téléphone détecté - Peut être utilisé pour spam/fraude', suggestion: 'Partager le numéro uniquement via des canaux sécurisés' },
      email: { message: 'Adresse e-mail détectée - Risque de spam et phishing', suggestion: 'Partager l\'e-mail uniquement avec des contacts de confiance' },
      password: { message: 'Mot de passe possible détecté - Ne jamais partager!', suggestion: 'Utiliser un gestionnaire de mots de passe' },
      vacation_hint: { message: 'Indice d\'absence détecté - Les cambrioleurs pourraient l\'utiliser', suggestion: 'Publier les absences seulement après le retour' }
    },
    contextWarnings: {
      whatsapp: 'Les messages WhatsApp peuvent être transférés',
      email: 'Les e-mails peuvent être transmis non chiffrés',
      social: 'Les publications sur les réseaux sociaux peuvent être visibles publiquement',
      default: 'Considérez qui pourrait lire ce message'
    }
  },
  es: {
    riskLevels: {
      safe: 'Seguro',
      warning: 'Atención',
      danger: 'Peligro'
    },
    summary: {
      noRisks: 'No se detectaron riesgos',
      risks: '{count} riesgos potenciales detectados'
    },
    categories: {
      iban: { message: 'IBAN detectado - Nunca compartir en chats', suggestion: 'Enviar datos bancarios por canal seguro' },
      credit_card: { message: 'Número de tarjeta de crédito detectado - Alto riesgo de fraude', suggestion: 'Nunca compartir datos de tarjeta en mensajes' },
      phone: { message: 'Número de teléfono detectado - Puede usarse para spam/fraude', suggestion: 'Compartir número solo por canales seguros' },
      email: { message: 'Dirección de correo detectada - Riesgo de spam y phishing', suggestion: 'Compartir correo solo con contactos de confianza' },
      password: { message: 'Posible contraseña detectada - ¡Nunca compartir!', suggestion: 'Usar un gestor de contraseñas' },
      vacation_hint: { message: 'Indicio de ausencia detectado - Los ladrones podrían usarlo', suggestion: 'Publicar ausencias solo después de volver' }
    },
    contextWarnings: {
      whatsapp: 'Los mensajes de WhatsApp pueden ser reenviados',
      email: 'Los correos pueden transmitirse sin cifrar',
      social: 'Las publicaciones en redes sociales pueden ser visibles públicamente',
      default: 'Considera quién podría leer este mensaje'
    }
  },
  it: {
    riskLevels: {
      safe: 'Sicuro',
      warning: 'Attenzione',
      danger: 'Pericolo'
    },
    summary: {
      noRisks: 'Nessun rischio rilevato',
      risks: '{count} rischi potenziali rilevati'
    },
    categories: {
      iban: { message: 'IBAN rilevato - Mai condividere nelle chat', suggestion: 'Inviare dati bancari tramite canale sicuro' },
      credit_card: { message: 'Numero carta di credito rilevato - Alto rischio frode', suggestion: 'Mai condividere dati carta nei messaggi' },
      phone: { message: 'Numero di telefono rilevato - Può essere usato per spam/frode', suggestion: 'Condividere numero solo tramite canali sicuri' },
      email: { message: 'Indirizzo email rilevato - Rischio spam e phishing', suggestion: 'Condividere email solo con contatti fidati' },
      password: { message: 'Possibile password rilevata - Mai condividere!', suggestion: 'Usare un gestore di password' },
      vacation_hint: { message: 'Indicazione di assenza rilevata - I ladri potrebbero usarla', suggestion: 'Pubblicare assenze solo dopo il ritorno' }
    },
    contextWarnings: {
      whatsapp: 'I messaggi WhatsApp possono essere inoltrati',
      email: 'Le email possono essere trasmesse non crittografate',
      social: 'I post sui social media possono essere visibili pubblicamente',
      default: 'Considera chi potrebbe leggere questo messaggio'
    }
  }
};

// Helper: Get localized message for a category
function getLocalizedCategory(type, lang = 'de') {
  const locale = LOCALES[lang] || LOCALES[DEFAULT_LANGUAGE];
  const category = locale.categories[type];
  if (category) {
    return category;
  }
  // Fallback to German if not found in target language
  return LOCALES.de.categories[type] || { message: type, suggestion: '' };
}

// Helper: Get localized context warning
function getLocalizedContextWarning(context, lang = 'de') {
  const locale = LOCALES[lang] || LOCALES[DEFAULT_LANGUAGE];
  return locale.contextWarnings[context.toLowerCase()] || locale.contextWarnings.default;
}

// Helper: Get localized summary
function getLocalizedSummary(count, lang = 'de') {
  const locale = LOCALES[lang] || LOCALES[DEFAULT_LANGUAGE];
  if (count === 0) {
    return locale.summary.noRisks;
  }
  return locale.summary.risks.replace('{count}', count);
}

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
  },
  address: {
    regex: /\b(?:Straße|Str\.|Weg|Platz|Allee|Gasse|Ring|Ufer|Damm|Chaussee)\s+\d+[a-z]?\b/gi,
    severity: 'medium',
    category: 'location',
    message: 'Straßenadresse erkannt',
    suggestion: 'Adressen können zur Lokalisierung genutzt werden'
  },
  postal_code: {
    regex: /\b\d{5}\s+[A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?\b/g,
    severity: 'low',
    category: 'location',
    message: 'Postleitzahl mit Ort erkannt',
    suggestion: 'PLZ+Ort ermöglicht grobe Standortbestimmung'
  },

  // === Context/Behavior ===
  vacation_hint: {
    regex: /(?:urlaub|verreist|nicht\s+(?:zu\s+)?hause|weg\s+(?:vom|von)|abwesend|unterwegs\s+nach|fliege\s+(?:nach|morgen)|bin\s+(?:weg|nicht\s+da))/gi,
    severity: 'medium',
    category: 'context',
    message: 'Abwesenheitshinweis erkannt - Einbrecher könnten dies nutzen',
    suggestion: 'Abwesenheiten erst nach Rückkehr posten'
  },
  german_date: {
    regex: /\b\d{1,2}\.\d{1,2}\.\d{2,4}\b/g,
    severity: 'low',
    category: 'personal',
    message: 'Datum erkannt',
    suggestion: 'Daten können zur Identifizierung beitragen'
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
    types: ['gps_coordinates', 'license_plate', 'address', 'postal_code']
  },
  context: {
    name: 'Kontextbezogene Risiken',
    description: 'Verhaltens- und situationsbezogene Informationen',
    types: ['vacation_hint', 'german_date']
  },
  semantic: {
    name: 'Semantische Erkennung (GPT)',
    description: 'Kontextabhängige Erkennung durch KI',
    types: ['health', 'child', 'location', 'emotion', 'employer', 'vacation', 'legal', 'gender', 'religion', 'political', 'biometric', 'photo']
  }
};

// ===========================================
// Phase 5: Predictive Privacy Data Structures
// ===========================================

// Risk factors with uniqueness scores (higher = more unique = more dangerous)
const RISK_FACTORS = {
  // Financial - very high uniqueness
  iban: { uniquenessScore: 0.95, category: 'financial', description: 'Bankverbindung ist quasi-eindeutig identifizierbar' },
  credit_card: { uniquenessScore: 0.98, category: 'financial', description: 'Kreditkartennummer ist eindeutig und sehr wertvoll' },
  bic: { uniquenessScore: 0.3, category: 'financial', description: 'BIC identifiziert nur die Bank, nicht den Inhaber' },
  account_number: { uniquenessScore: 0.85, category: 'financial', description: 'Kontonummer in Kombination mit Bank identifizierbar' },

  // Identity - highest uniqueness
  national_id: { uniquenessScore: 0.99, category: 'identity', description: 'Personalausweisnummer ist eindeutig für eine Person' },
  passport: { uniquenessScore: 0.99, category: 'identity', description: 'Reisepassnummer ist eindeutig' },
  tax_id: { uniquenessScore: 0.99, category: 'identity', description: 'Steuer-ID ist lebenslang eindeutig' },
  social_security: { uniquenessScore: 0.99, category: 'identity', description: 'Sozialversicherungsnummer ist eindeutig' },
  drivers_license: { uniquenessScore: 0.95, category: 'identity', description: 'Führerscheinnummer ist eindeutig' },

  // Health - high sensitivity
  health_insurance: { uniquenessScore: 0.9, category: 'health', description: 'Krankenversicherungsnummer ist personenbezogen' },
  medical_record: { uniquenessScore: 0.85, category: 'health', description: 'Patientennummer ist innerhalb des Systems eindeutig' },

  // Digital - varies
  ip_address: { uniquenessScore: 0.4, category: 'digital', description: 'IP kann sich ändern, Geolocation möglich' },
  mac_address: { uniquenessScore: 0.8, category: 'digital', description: 'MAC identifiziert Gerät eindeutig' },
  username: { uniquenessScore: 0.6, category: 'digital', description: 'Usernames können oft mit Personen verknüpft werden' },
  password: { uniquenessScore: 0.9, category: 'digital', description: 'Passwörter ermöglichen direkten Zugriff' },
  api_key: { uniquenessScore: 0.95, category: 'digital', description: 'API-Keys sind systemweit eindeutig' },

  // Personal - medium to high
  phone: { uniquenessScore: 0.85, category: 'personal', description: 'Telefonnummern sind meist personengebunden' },
  email: { uniquenessScore: 0.8, category: 'personal', description: 'E-Mail-Adressen sind oft eindeutig identifizierbar' },
  date_of_birth: { uniquenessScore: 0.15, category: 'personal', description: 'Allein wenig eindeutig, in Kombination wichtig' },
  age: { uniquenessScore: 0.05, category: 'personal', description: 'Alter allein nicht identifizierend' },

  // Location - context dependent
  gps_coordinates: { uniquenessScore: 0.7, category: 'location', description: 'GPS kann Wohn-/Arbeitsort verraten' },
  license_plate: { uniquenessScore: 0.9, category: 'location', description: 'Kennzeichen ist Halter zugeordnet' },
  address: { uniquenessScore: 0.75, category: 'location', description: 'Adresse identifiziert Wohnort' },
  postal_code: { uniquenessScore: 0.2, category: 'location', description: 'PLZ grenzt Region ein' },

  // Context/Semantic
  vacation_hint: { uniquenessScore: 0.1, category: 'context', description: 'Abwesenheitsinfo ist zeitlich relevant' },
  german_date: { uniquenessScore: 0.05, category: 'personal', description: 'Datum allein nicht identifizierend' },
  health: { uniquenessScore: 0.6, category: 'semantic', description: 'Gesundheitsinfos können identifizierend sein' },
  child: { uniquenessScore: 0.7, category: 'semantic', description: 'Kinderdaten + Kontext sehr sensibel' },
  location: { uniquenessScore: 0.5, category: 'semantic', description: 'Semantische Standortinfos' },
  emotion: { uniquenessScore: 0.2, category: 'semantic', description: 'Emotionen selten identifizierend' },
  employer: { uniquenessScore: 0.4, category: 'semantic', description: 'Arbeitgeber in Kombination relevant' },
  vacation: { uniquenessScore: 0.15, category: 'semantic', description: 'Urlaubsinfo zeitlich relevant' },
  legal: { uniquenessScore: 0.3, category: 'semantic', description: 'Rechtliche Aussagen kontextabhängig' }
};

// Breach scenarios with impact assessment
const BREACH_SCENARIOS = [
  {
    id: 'data_broker',
    name: 'Datenbroker-Verkauf',
    description: 'Daten werden an Datenbroker verkauft und mit anderen Quellen kombiniert',
    probability: 0.4,
    relevantTypes: ['email', 'phone', 'address', 'postal_code', 'date_of_birth', 'age'],
    consequences: [
      'Zielgerichtete Werbung und Tracking',
      'Profilerstellung über verschiedene Plattformen',
      'Weiterverkauf an Dritte'
    ],
    timeToImpact: 'sofort bis Wochen',
    mitigations: ['Einwegadressen nutzen', 'Virtuelle Telefonnummern', 'Privacy-Browser']
  },
  {
    id: 'identity_theft',
    name: 'Identitätsdiebstahl',
    description: 'Kriminelle nutzen persönliche Daten für Betrug oder Identitätsdiebstahl',
    probability: 0.25,
    relevantTypes: ['national_id', 'passport', 'tax_id', 'social_security', 'drivers_license', 'date_of_birth', 'address'],
    consequences: [
      'Eröffnung von Konten/Krediten in deinem Namen',
      'Steuerbetrug mit deiner ID',
      'Kriminelle Handlungen unter falscher Identität'
    ],
    timeToImpact: 'Tage bis Monate',
    mitigations: ['SCHUFA-Auskunft sperren', 'Behörden informieren', 'Bonitätsüberwachung aktivieren']
  },
  {
    id: 'financial_fraud',
    name: 'Finanzbetrug',
    description: 'Angreifer nutzen Finanzdaten für unberechtigte Transaktionen',
    probability: 0.35,
    relevantTypes: ['iban', 'credit_card', 'bic', 'account_number'],
    consequences: [
      'Unberechtigte Abbuchungen',
      'Kreditkartenbetrug',
      'Überweisungsbetrug'
    ],
    timeToImpact: 'Stunden bis Tage',
    mitigations: ['Bank sofort informieren', 'Karte sperren', 'Transaktionen überwachen']
  },
  {
    id: 'phishing_targeted',
    name: 'Gezieltes Phishing',
    description: 'Personalisierte Betrugsversuche basierend auf gesammelten Daten',
    probability: 0.5,
    relevantTypes: ['email', 'phone', 'employer', 'health', 'child'],
    consequences: [
      'Überzeugendere Phishing-Nachrichten',
      'CEO-Fraud / Business Email Compromise',
      'Soziale Manipulation durch Kontextkenntnis'
    ],
    timeToImpact: 'Tage bis Wochen',
    mitigations: ['Zwei-Faktor-Authentifizierung', 'Schulung für Phishing-Erkennung', 'Rückruf bei verdächtigen Anfragen']
  },
  {
    id: 'physical_stalking',
    name: 'Physisches Stalking',
    description: 'Standortdaten ermöglichen reale Verfolgung',
    probability: 0.15,
    relevantTypes: ['gps_coordinates', 'address', 'license_plate', 'vacation_hint', 'vacation', 'location'],
    consequences: [
      'Physische Verfolgung',
      'Einbruch während Abwesenheit',
      'Belästigung am Wohnort/Arbeitsplatz'
    ],
    timeToImpact: 'sofort',
    mitigations: ['Standortdaten nie öffentlich teilen', 'Urlaub erst nach Rückkehr posten', 'Sicherheitsvorkehrungen treffen']
  },
  {
    id: 'medical_discrimination',
    name: 'Gesundheitsdiskriminierung',
    description: 'Gesundheitsdaten führen zu Benachteiligungen',
    probability: 0.2,
    relevantTypes: ['health_insurance', 'medical_record', 'health'],
    consequences: [
      'Versicherungsablehnung/-erhöhung',
      'Arbeitgeberdiskriminierung',
      'Soziale Stigmatisierung'
    ],
    timeToImpact: 'Wochen bis Jahre',
    mitigations: ['Gesundheitsdaten nur verschlüsselt teilen', 'Recht auf Löschung nutzen', 'DSGVO-Beschwerden']
  },
  {
    id: 'credential_stuffing',
    name: 'Credential Stuffing',
    description: 'Geleakte Zugangsdaten werden für automatisierte Einbruchsversuche genutzt',
    probability: 0.6,
    relevantTypes: ['password', 'username', 'email', 'api_key'],
    consequences: [
      'Übernahme von Accounts',
      'Kettenreaktion bei Passwort-Wiederverwendung',
      'Finanzieller Schaden durch kompromittierte Dienste'
    ],
    timeToImpact: 'Minuten bis Stunden',
    mitigations: ['Einzigartige Passwörter pro Dienst', 'Passwort-Manager', 'Sofortige Passwortänderung bei Leak']
  },
  {
    id: 'child_exploitation',
    name: 'Gefährdung von Kindern',
    description: 'Kinderdaten werden für Manipulations- oder Gefährdungszwecke missbraucht',
    probability: 0.1,
    relevantTypes: ['child'],
    consequences: [
      'Annäherungsversuche an Minderjährige',
      'Soziale Manipulation über Kinder',
      'Langfristige Profilerstellung von Minderjährigen'
    ],
    timeToImpact: 'variabel',
    mitigations: ['Kinderdaten niemals öffentlich teilen', 'Schulnamen etc. anonymisieren', 'Kinderfotos ohne Gesicht']
  }
];

// Correlation attack methods
const CORRELATION_METHODS = [
  {
    id: 'cross_platform',
    name: 'Plattformübergreifende Korrelation',
    description: 'Kombination von Daten aus verschiedenen sozialen Netzwerken',
    dataPoints: ['username', 'email', 'phone', 'photo_metadata'],
    difficulty: 'mittel',
    effectiveness: 0.7,
    example: 'Username "MaxM89" erscheint auf Twitter, LinkedIn und Gaming-Forum → vollständiges Profil'
  },
  {
    id: 'temporal_location',
    name: 'Zeitliche Standortanalyse',
    description: 'Verknüpfung von Standortdaten über Zeit',
    dataPoints: ['gps_coordinates', 'address', 'postal_code', 'vacation_hint'],
    difficulty: 'niedrig',
    effectiveness: 0.8,
    example: 'Mehrere Standort-Posts = Bewegungsprofil → Wohnort und Arbeitsplatz identifizierbar'
  },
  {
    id: 'social_graph',
    name: 'Soziales Netzwerk-Mapping',
    description: 'Rekonstruktion des sozialen Umfelds aus verschiedenen Quellen',
    dataPoints: ['employer', 'child', 'phone', 'email'],
    difficulty: 'mittel',
    effectiveness: 0.6,
    example: 'Erwähnung von Kollegen + Firma + Schulen der Kinder → komplettes Umfeld'
  },
  {
    id: 'financial_pattern',
    name: 'Finanzielle Verhaltensanalyse',
    description: 'Kombination von Finanzdaten für Profilierung',
    dataPoints: ['iban', 'credit_card', 'account_number'],
    difficulty: 'hoch',
    effectiveness: 0.5,
    example: 'IBAN + Transaktionsmuster = Einkommensschätzung und Ausgabeverhalten'
  },
  {
    id: 'biometric_link',
    name: 'Biometrische Verknüpfung',
    description: 'Gesichtserkennung und Bildanalyse über Plattformen',
    dataPoints: ['photo', 'video', 'social_media_profile'],
    difficulty: 'mittel',
    effectiveness: 0.75,
    example: 'Profilbild-Suche findet gleiche Person auf anderen Plattformen'
  },
  {
    id: 'linguistic_fingerprint',
    name: 'Linguistische Analyse',
    description: 'Schreibstil-Analyse zur Identifikation',
    dataPoints: ['text_samples', 'comments', 'posts'],
    difficulty: 'hoch',
    effectiveness: 0.4,
    example: 'Charakteristischer Schreibstil verknüpft anonyme Posts mit bekanntem Account'
  },
  {
    id: 'device_fingerprint',
    name: 'Geräte-Fingerprinting',
    description: 'Identifikation über eindeutige Geräteeigenschaften',
    dataPoints: ['ip_address', 'mac_address', 'browser_fingerprint'],
    difficulty: 'niedrig',
    effectiveness: 0.85,
    example: 'Kombination aus Browser-Version, Plugins, Bildschirmauflösung ist oft eindeutig'
  },
  {
    id: 'metadata_analysis',
    name: 'Metadaten-Auswertung',
    description: 'Analyse versteckter Daten in Dateien',
    dataPoints: ['photo_exif', 'document_metadata', 'gps_coordinates'],
    difficulty: 'niedrig',
    effectiveness: 0.7,
    example: 'EXIF-Daten in Foto enthalten GPS-Koordinaten, Kameramodell und Zeitstempel'
  }
];

// ===========================================
// Phase 7: Digital Footprint Scanner Data
// ===========================================

// Known data breaches database
const BREACH_DATABASE = [
  {
    id: 'linkedin_2021',
    name: 'LinkedIn',
    domain: 'linkedin.com',
    date: '2021-06-22',
    addedDate: '2021-06-29',
    compromisedAccounts: 700000000,
    dataClasses: ['email', 'name', 'phone', 'workplace', 'education', 'profile_url'],
    description: 'Massive Datenpanne durch API-Scraping. 700 Millionen Nutzerdaten wurden im Dark Web zum Verkauf angeboten.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'facebook_2019',
    name: 'Facebook',
    domain: 'facebook.com',
    date: '2019-04-03',
    addedDate: '2021-04-06',
    compromisedAccounts: 533000000,
    dataClasses: ['email', 'phone', 'name', 'location', 'relationship_status', 'employer'],
    description: 'Telefonnummern und persönliche Daten von 533 Millionen Facebook-Nutzern aus 106 Ländern wurden geleakt.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'twitter_2023',
    name: 'Twitter/X',
    domain: 'twitter.com',
    date: '2023-01-05',
    addedDate: '2023-01-06',
    compromisedAccounts: 200000000,
    dataClasses: ['email', 'name', 'username', 'phone'],
    description: 'Email-Adressen von 200 Millionen Twitter-Nutzern wurden durch eine API-Schwachstelle exponiert.',
    severity: 'medium',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'adobe_2013',
    name: 'Adobe',
    domain: 'adobe.com',
    date: '2013-10-04',
    addedDate: '2013-12-04',
    compromisedAccounts: 153000000,
    dataClasses: ['email', 'password_hash', 'username', 'password_hint'],
    description: 'Eines der größten Datenlecks der Geschichte. Passwörter waren nur schwach verschlüsselt.',
    severity: 'critical',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'dropbox_2012',
    name: 'Dropbox',
    domain: 'dropbox.com',
    date: '2012-07-01',
    addedDate: '2016-08-31',
    compromisedAccounts: 68648009,
    dataClasses: ['email', 'password_hash'],
    description: 'Über 68 Millionen Dropbox-Zugangsdaten wurden gestohlen und später im Dark Web veröffentlicht.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'myspace_2008',
    name: 'MySpace',
    domain: 'myspace.com',
    date: '2008-07-01',
    addedDate: '2016-05-31',
    compromisedAccounts: 359420698,
    dataClasses: ['email', 'password_hash', 'username'],
    description: 'Historisches Datenleck mit über 360 Millionen Accounts. Passwörter wurden 2016 geknackt.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'canva_2019',
    name: 'Canva',
    domain: 'canva.com',
    date: '2019-05-24',
    addedDate: '2019-05-24',
    compromisedAccounts: 137000000,
    dataClasses: ['email', 'name', 'username', 'password_hash', 'location'],
    description: 'Grafikdesign-Plattform erlitt Datenleck mit 137 Millionen Nutzerkonten.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'zynga_2019',
    name: 'Zynga',
    domain: 'zynga.com',
    date: '2019-09-01',
    addedDate: '2019-09-12',
    compromisedAccounts: 173000000,
    dataClasses: ['email', 'username', 'password_hash', 'phone'],
    description: 'Spieleentwickler Zynga (Words with Friends) wurde gehackt, 173 Millionen Accounts betroffen.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'marriott_2018',
    name: 'Marriott Starwood',
    domain: 'marriott.com',
    date: '2018-11-30',
    addedDate: '2018-11-30',
    compromisedAccounts: 500000000,
    dataClasses: ['email', 'name', 'phone', 'passport_number', 'credit_card', 'address'],
    description: 'Hotelkette Marriott erlitt massiven Hack. Passnummern und Kreditkartendaten betroffen.',
    severity: 'critical',
    isVerified: true,
    isSensitive: true,
    affectedCountries: ['Global']
  },
  {
    id: 'yahoo_2013',
    name: 'Yahoo',
    domain: 'yahoo.com',
    date: '2013-08-01',
    addedDate: '2016-12-14',
    compromisedAccounts: 3000000000,
    dataClasses: ['email', 'password_hash', 'name', 'phone', 'security_questions'],
    description: 'Größter Hack der Geschichte. Alle 3 Milliarden Yahoo-Accounts waren betroffen.',
    severity: 'critical',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'dubsmash_2018',
    name: 'Dubsmash',
    domain: 'dubsmash.com',
    date: '2018-12-01',
    addedDate: '2019-02-14',
    compromisedAccounts: 162000000,
    dataClasses: ['email', 'username', 'password_hash', 'name'],
    description: 'Video-App Dubsmash wurde gehackt, Daten im Dark Web verkauft.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'exactis_2018',
    name: 'Exactis',
    domain: 'exactis.com',
    date: '2018-06-01',
    addedDate: '2018-06-27',
    compromisedAccounts: 340000000,
    dataClasses: ['email', 'name', 'phone', 'address', 'interests', 'habits', 'children', 'religion'],
    description: 'Marketing-Firma leakte 340 Millionen detaillierte Personenprofile öffentlich.',
    severity: 'critical',
    isVerified: true,
    isSensitive: true,
    affectedCountries: ['US']
  },
  {
    id: 'equifax_2017',
    name: 'Equifax',
    domain: 'equifax.com',
    date: '2017-07-29',
    addedDate: '2017-09-07',
    compromisedAccounts: 147900000,
    dataClasses: ['name', 'social_security_number', 'birth_date', 'address', 'drivers_license', 'credit_card'],
    description: 'Kredit-Auskunftei Equifax wurde gehackt. SSN und Finanzdaten von 148 Mio. Amerikanern betroffen.',
    severity: 'critical',
    isVerified: true,
    isSensitive: true,
    affectedCountries: ['US', 'UK', 'CA']
  },
  {
    id: 'spotify_2020',
    name: 'Spotify',
    domain: 'spotify.com',
    date: '2020-11-23',
    addedDate: '2020-11-24',
    compromisedAccounts: 350000,
    dataClasses: ['email', 'username', 'password'],
    description: 'Credential-Stuffing-Angriff auf Spotify mit 350.000 kompromittierten Accounts.',
    severity: 'medium',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'twitch_2021',
    name: 'Twitch',
    domain: 'twitch.tv',
    date: '2021-10-06',
    addedDate: '2021-10-06',
    compromisedAccounts: 0,
    dataClasses: ['source_code', 'streamer_payouts', 'internal_tools'],
    description: 'Kompletter Quellcode und interne Daten von Twitch wurden geleakt.',
    severity: 'high',
    isVerified: true,
    isSensitive: true,
    affectedCountries: ['Global']
  },
  {
    id: 'tmobile_2021',
    name: 'T-Mobile',
    domain: 't-mobile.com',
    date: '2021-08-17',
    addedDate: '2021-08-17',
    compromisedAccounts: 77000000,
    dataClasses: ['name', 'social_security_number', 'drivers_license', 'phone', 'address', 'birth_date'],
    description: 'T-Mobile USA wurde gehackt, SSN und Führerscheindaten von 77 Mio. Kunden betroffen.',
    severity: 'critical',
    isVerified: true,
    isSensitive: true,
    affectedCountries: ['US']
  },
  {
    id: 'lastfm_2012',
    name: 'Last.fm',
    domain: 'last.fm',
    date: '2012-03-22',
    addedDate: '2016-09-01',
    compromisedAccounts: 37217682,
    dataClasses: ['email', 'username', 'password_hash'],
    description: 'Musik-Streaming-Dienst Last.fm wurde gehackt, Passwörter waren schwach gehasht.',
    severity: 'medium',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'deezer_2019',
    name: 'Deezer',
    domain: 'deezer.com',
    date: '2019-09-01',
    addedDate: '2023-01-02',
    compromisedAccounts: 229000000,
    dataClasses: ['email', 'username', 'name', 'ip_address', 'birth_date', 'location'],
    description: 'Musik-Streaming-Dienst Deezer erlitt Datenleck mit 229 Millionen Nutzerkonten.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'wattpad_2020',
    name: 'Wattpad',
    domain: 'wattpad.com',
    date: '2020-06-29',
    addedDate: '2020-07-14',
    compromisedAccounts: 271000000,
    dataClasses: ['email', 'username', 'password_hash', 'name', 'birth_date', 'ip_address'],
    description: 'Storytelling-Plattform Wattpad wurde gehackt, 271 Millionen Accounts betroffen.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  },
  {
    id: 'mgm_2019',
    name: 'MGM Resorts',
    domain: 'mgmresorts.com',
    date: '2019-07-01',
    addedDate: '2020-02-19',
    compromisedAccounts: 142000000,
    dataClasses: ['name', 'email', 'phone', 'address', 'birth_date'],
    description: 'Hotel- und Casino-Betreiber MGM erlitt Datenleck mit 142 Millionen Gästedaten.',
    severity: 'high',
    isVerified: true,
    isSensitive: false,
    affectedCountries: ['Global']
  }
];

// Data broker database (50+ entries)
const DATA_BROKERS = [
  // People Search - US
  {
    id: 'spokeo',
    name: 'Spokeo',
    website: 'spokeo.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'relatives', 'social_profiles', 'photos'],
    sources: ['public_records', 'social_media', 'marketing_lists', 'phone_directories'],
    optOut: {
      available: true,
      url: 'https://www.spokeo.com/optout',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: false,
      instructions: [
        'Besuchen Sie die Opt-out Seite',
        'Suchen Sie Ihr Profil',
        'Kopieren Sie die Profil-URL',
        'Geben Sie Ihre Email ein',
        'Bestätigen Sie den Link in der Email'
      ]
    },
    riskLevel: 'high',
    description: 'Einer der größten People-Search-Dienste. Aggregiert Daten aus öffentlichen Quellen.'
  },
  {
    id: 'beenverified',
    name: 'BeenVerified',
    website: 'beenverified.com',
    category: 'background_check',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'criminal_records', 'court_records', 'assets'],
    sources: ['public_records', 'court_records', 'property_records'],
    optOut: {
      available: true,
      url: 'https://www.beenverified.com/f/optout/search',
      method: 'web_form',
      requiresId: false,
      difficulty: 'medium',
      estimatedDays: 7,
      gdprCompliant: false,
      instructions: [
        'Besuchen Sie die Opt-out Seite',
        'Suchen Sie Ihr Profil',
        'Klicken Sie auf Opt-out',
        'Verifizieren Sie per Email'
      ]
    },
    riskLevel: 'high',
    description: 'Background-Check-Dienst mit umfangreichen öffentlichen Daten.'
  },
  {
    id: 'whitepages',
    name: 'Whitepages',
    website: 'whitepages.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'relatives', 'neighbors'],
    sources: ['public_records', 'phone_directories', 'marketing_lists'],
    optOut: {
      available: true,
      url: 'https://www.whitepages.com/suppression-requests',
      method: 'web_form',
      requiresId: true,
      difficulty: 'medium',
      estimatedDays: 5,
      gdprCompliant: false,
      instructions: [
        'Suchen Sie Ihr Profil auf Whitepages',
        'Kopieren Sie die URL',
        'Gehen Sie zur Opt-out-Seite',
        'Verifizieren Sie per Telefon'
      ]
    },
    riskLevel: 'high',
    description: 'Klassisches Telefonbuch mit erweiterten Personendaten.'
  },
  {
    id: 'intelius',
    name: 'Intelius',
    website: 'intelius.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'criminal_records', 'relatives', 'employment'],
    sources: ['public_records', 'court_records', 'marketing_data'],
    optOut: {
      available: true,
      url: 'https://www.intelius.com/opt-out',
      method: 'web_form',
      requiresId: true,
      difficulty: 'medium',
      estimatedDays: 7,
      gdprCompliant: false,
      instructions: [
        'Faxen Sie einen Opt-out-Antrag',
        'Oder nutzen Sie das Online-Formular',
        'ID-Verifizierung erforderlich'
      ]
    },
    riskLevel: 'high',
    description: 'Umfassender Personensuchdienst mit Background-Checks.'
  },
  {
    id: 'peoplefinder',
    name: 'PeopleFinder',
    website: 'peoplefinder.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'age', 'relatives'],
    sources: ['public_records', 'phone_directories'],
    optOut: {
      available: true,
      url: 'https://www.peoplefinder.com/optout.php',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: false,
      instructions: [
        'Suchen Sie Ihr Profil',
        'Klicken Sie auf Opt-out',
        'Bestätigen Sie per Email'
      ]
    },
    riskLevel: 'medium',
    description: 'Personensuchdienst mit Fokus auf Adressdaten.'
  },
  {
    id: 'truepeoplesearch',
    name: 'TruePeopleSearch',
    website: 'truepeoplesearch.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'relatives', 'associates'],
    sources: ['public_records', 'social_media'],
    optOut: {
      available: true,
      url: 'https://www.truepeoplesearch.com/removal',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 1,
      gdprCompliant: false,
      instructions: [
        'Suchen Sie Ihr Profil',
        'Klicken Sie auf Remove This Record',
        'Captcha lösen'
      ]
    },
    riskLevel: 'high',
    description: 'Kostenloser Personensuchdienst - besonders problematisch.'
  },
  {
    id: 'fastpeoplesearch',
    name: 'FastPeopleSearch',
    website: 'fastpeoplesearch.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'age', 'relatives'],
    sources: ['public_records'],
    optOut: {
      available: true,
      url: 'https://www.fastpeoplesearch.com/removal',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 1,
      gdprCompliant: false,
      instructions: [
        'Suchen Sie Ihr Profil',
        'Klicken Sie Remove Record',
        'Captcha lösen'
      ]
    },
    riskLevel: 'high',
    description: 'Kostenloser Personensuchdienst mit schnellem Opt-out.'
  },
  {
    id: 'radaris',
    name: 'Radaris',
    website: 'radaris.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'employment', 'education', 'criminal_records'],
    sources: ['public_records', 'social_media', 'court_records'],
    optOut: {
      available: true,
      url: 'https://radaris.com/control/privacy',
      method: 'web_form',
      requiresId: false,
      difficulty: 'medium',
      estimatedDays: 7,
      gdprCompliant: false,
      instructions: [
        'Erstellen Sie ein Konto',
        'Suchen Sie Ihr Profil',
        'Beantragen Sie Löschung'
      ]
    },
    riskLevel: 'high',
    description: 'Umfassender Personensuchdienst mit vielen Datenquellen.'
  },
  // Marketing Data - Global
  {
    id: 'acxiom',
    name: 'Acxiom',
    website: 'acxiom.com',
    category: 'marketing_data',
    region: 'Global',
    dataCollected: ['name', 'address', 'purchase_history', 'demographics', 'interests', 'lifestyle'],
    sources: ['retailers', 'surveys', 'public_records', 'credit_cards'],
    optOut: {
      available: true,
      url: 'https://isapps.acxiom.com/optout/optout.aspx',
      method: 'web_form',
      requiresId: true,
      difficulty: 'medium',
      estimatedDays: 45,
      gdprCompliant: true,
      instructions: [
        'Besuchen Sie die Opt-out-Seite',
        'Füllen Sie das Formular aus',
        'SSN oder andere ID angeben',
        'Warten Sie auf Bestätigung'
      ]
    },
    riskLevel: 'high',
    description: 'Einer der größten Datenbroker weltweit. Sammelt detaillierte Konsumentenprofile.'
  },
  {
    id: 'oracle_datacloud',
    name: 'Oracle Data Cloud',
    website: 'oracle.com/data-cloud',
    category: 'marketing_data',
    region: 'Global',
    dataCollected: ['name', 'purchase_history', 'browsing_behavior', 'demographics', 'location'],
    sources: ['websites', 'apps', 'retailers', 'data_partners'],
    optOut: {
      available: true,
      url: 'https://www.oracle.com/legal/privacy/marketing-cloud-data-cloud-privacy-policy.html#optout',
      method: 'web_form',
      requiresId: false,
      difficulty: 'medium',
      estimatedDays: 30,
      gdprCompliant: true,
      instructions: [
        'Besuchen Sie die Privacy-Seite',
        'Nutzen Sie das Opt-out-Tool',
        'Cookie-basiertes Opt-out möglich'
      ]
    },
    riskLevel: 'high',
    description: 'Oracles Marketing-Datenplattform mit Milliarden von Profilen.'
  },
  {
    id: 'epsilon',
    name: 'Epsilon',
    website: 'epsilon.com',
    category: 'marketing_data',
    region: 'Global',
    dataCollected: ['name', 'address', 'email', 'purchase_history', 'demographics'],
    sources: ['retailers', 'loyalty_programs', 'surveys'],
    optOut: {
      available: true,
      url: 'https://www.epsilon.com/privacy-policy',
      method: 'email',
      requiresId: false,
      difficulty: 'medium',
      estimatedDays: 30,
      gdprCompliant: true,
      instructions: [
        'Senden Sie eine Email an privacy@epsilon.com',
        'Geben Sie Ihre Daten an',
        'Beantragen Sie Löschung'
      ]
    },
    riskLevel: 'medium',
    description: 'Marketing-Datenunternehmen im Besitz von Publicis.'
  },
  // Credit Reporting - Global
  {
    id: 'experian',
    name: 'Experian',
    website: 'experian.com',
    category: 'credit_reporting',
    region: 'Global',
    dataCollected: ['name', 'address', 'ssn', 'credit_history', 'employment', 'bank_accounts'],
    sources: ['banks', 'credit_cards', 'loans', 'utilities'],
    optOut: {
      available: false,
      url: 'https://www.experian.com/privacy',
      method: 'mail',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 90,
      gdprCompliant: true,
      instructions: [
        'Kein vollständiges Opt-out möglich',
        'Marketing Opt-out verfügbar',
        'Datensperrung bei Identitätsdiebstahl'
      ]
    },
    riskLevel: 'high',
    description: 'Eine der drei großen Kreditauskunfteien. Opt-out stark eingeschränkt.'
  },
  {
    id: 'equifax',
    name: 'Equifax',
    website: 'equifax.com',
    category: 'credit_reporting',
    region: 'Global',
    dataCollected: ['name', 'address', 'ssn', 'credit_history', 'employment', 'bank_accounts'],
    sources: ['banks', 'credit_cards', 'loans', 'utilities'],
    optOut: {
      available: false,
      url: 'https://www.equifax.com/personal/privacy',
      method: 'mail',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 90,
      gdprCompliant: true,
      instructions: [
        'Kein vollständiges Opt-out möglich',
        'Kredit-Freeze möglich',
        'Marketing Opt-out verfügbar'
      ]
    },
    riskLevel: 'high',
    description: 'Große Kreditauskunftei. War 2017 von massivem Datenleck betroffen.'
  },
  {
    id: 'transunion',
    name: 'TransUnion',
    website: 'transunion.com',
    category: 'credit_reporting',
    region: 'Global',
    dataCollected: ['name', 'address', 'ssn', 'credit_history', 'employment'],
    sources: ['banks', 'credit_cards', 'loans'],
    optOut: {
      available: false,
      url: 'https://www.transunion.com/privacy',
      method: 'mail',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 90,
      gdprCompliant: true,
      instructions: [
        'Kein vollständiges Opt-out möglich',
        'Kredit-Freeze empfohlen',
        'Marketing Opt-out verfügbar'
      ]
    },
    riskLevel: 'high',
    description: 'Die dritte große US-Kreditauskunftei.'
  },
  {
    id: 'schufa',
    name: 'SCHUFA',
    website: 'schufa.de',
    category: 'credit_reporting',
    region: 'EU',
    dataCollected: ['name', 'address', 'birth_date', 'credit_history', 'bank_accounts', 'contracts'],
    sources: ['banks', 'telecom', 'utilities', 'retailers'],
    optOut: {
      available: false,
      url: 'https://www.schufa.de/datenschutz',
      method: 'mail',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 30,
      gdprCompliant: true,
      instructions: [
        'Kein vollständiges Opt-out möglich',
        'Kostenlose Selbstauskunft nach DSGVO',
        'Fehlerhafte Einträge korrigierbar'
      ]
    },
    riskLevel: 'high',
    description: 'Deutsche Kreditauskunftei. DSGVO-Auskunftsrecht nutzen.'
  },
  // Background Check
  {
    id: 'lexisnexis',
    name: 'LexisNexis Risk Solutions',
    website: 'risk.lexisnexis.com',
    category: 'background_check',
    region: 'Global',
    dataCollected: ['name', 'address', 'ssn', 'criminal_records', 'driving_records', 'employment', 'education'],
    sources: ['court_records', 'dmv', 'public_records', 'credit_bureaus'],
    optOut: {
      available: true,
      url: 'https://consumer.risk.lexisnexis.com/request',
      method: 'mail',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 30,
      gdprCompliant: true,
      instructions: [
        'Kostenlose Auskunft anfordern',
        'Fehler korrigieren lassen',
        'Security Freeze möglich'
      ]
    },
    riskLevel: 'high',
    description: 'Großer Datenbroker für Background-Checks und Risikobewertung.'
  },
  {
    id: 'checkr',
    name: 'Checkr',
    website: 'checkr.com',
    category: 'background_check',
    region: 'US',
    dataCollected: ['name', 'ssn', 'criminal_records', 'driving_records', 'employment', 'education'],
    sources: ['court_records', 'dmv', 'employers'],
    optOut: {
      available: true,
      url: 'https://checkr.com/privacy',
      method: 'web_form',
      requiresId: true,
      difficulty: 'medium',
      estimatedDays: 14,
      gdprCompliant: true,
      instructions: [
        'Auskunft anfordern',
        'Fehler anfechten',
        'Löschung nach CCPA beantragen'
      ]
    },
    riskLevel: 'medium',
    description: 'Moderner Background-Check-Anbieter für Unternehmen.'
  },
  // People Search - Additional
  {
    id: 'pipl',
    name: 'Pipl',
    website: 'pipl.com',
    category: 'people_search',
    region: 'Global',
    dataCollected: ['name', 'email', 'phone', 'social_profiles', 'employment', 'education'],
    sources: ['social_media', 'public_records', 'web_scraping'],
    optOut: {
      available: true,
      url: 'https://pipl.com/personal-information-removal-request',
      method: 'web_form',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 14,
      gdprCompliant: true,
      instructions: [
        'Identitätsnachweis erforderlich',
        'Formular ausfüllen',
        'DSGVO-Antrag möglich'
      ]
    },
    riskLevel: 'high',
    description: 'Professioneller Personensuchdienst mit globaler Reichweite.'
  },
  {
    id: 'instantcheckmate',
    name: 'Instant Checkmate',
    website: 'instantcheckmate.com',
    category: 'background_check',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'criminal_records', 'relatives', 'social_profiles'],
    sources: ['public_records', 'court_records', 'social_media'],
    optOut: {
      available: true,
      url: 'https://www.instantcheckmate.com/opt-out',
      method: 'web_form',
      requiresId: false,
      difficulty: 'medium',
      estimatedDays: 7,
      gdprCompliant: false,
      instructions: [
        'Profil suchen',
        'Opt-out-Link anklicken',
        'Email bestätigen'
      ]
    },
    riskLevel: 'high',
    description: 'Background-Check-Dienst für Verbraucher.'
  },
  {
    id: 'usphonebook',
    name: 'USPhonebook',
    website: 'usphonebook.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone'],
    sources: ['phone_directories', 'public_records'],
    optOut: {
      available: true,
      url: 'https://www.usphonebook.com/opt-out',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: false,
      instructions: [
        'Telefonnummer eingeben',
        'Opt-out anklicken',
        'Bestätigen'
      ]
    },
    riskLevel: 'medium',
    description: 'Reverse Phone Lookup Dienst.'
  },
  {
    id: 'familytreenow',
    name: 'FamilyTreeNow',
    website: 'familytreenow.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'birth_date', 'relatives', 'neighbors', 'phone'],
    sources: ['public_records', 'genealogy_data'],
    optOut: {
      available: true,
      url: 'https://www.familytreenow.com/optout',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 2,
      gdprCompliant: false,
      instructions: [
        'Profil suchen',
        'Opt-out wählen',
        'Sofort entfernt'
      ]
    },
    riskLevel: 'high',
    description: 'Genealogie-basierter Personensuchdienst mit vielen Familiendaten.'
  },
  {
    id: 'cyberbackgroundchecks',
    name: 'CyberBackgroundChecks',
    website: 'cyberbackgroundchecks.com',
    category: 'background_check',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'criminal_records', 'court_records'],
    sources: ['public_records', 'court_records'],
    optOut: {
      available: true,
      url: 'https://www.cyberbackgroundchecks.com/removal',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: false,
      instructions: [
        'Profil-URL kopieren',
        'Removal-Formular ausfüllen',
        'Bestätigen'
      ]
    },
    riskLevel: 'medium',
    description: 'Online Background-Check-Service.'
  },
  // Recruitment/Professional
  {
    id: 'zoominfo',
    name: 'ZoomInfo',
    website: 'zoominfo.com',
    category: 'recruitment',
    region: 'Global',
    dataCollected: ['name', 'email', 'phone', 'employer', 'job_title', 'linkedin', 'company_info'],
    sources: ['email_signatures', 'websites', 'linkedin', 'business_cards'],
    optOut: {
      available: true,
      url: 'https://www.zoominfo.com/update/remove',
      method: 'web_form',
      requiresId: true,
      difficulty: 'medium',
      estimatedDays: 30,
      gdprCompliant: true,
      instructions: [
        'Profil suchen',
        'Löschung beantragen',
        'Unternehmens-Email erforderlich'
      ]
    },
    riskLevel: 'medium',
    description: 'B2B-Kontaktdatenbank für Sales und Recruiting.'
  },
  {
    id: 'lusha',
    name: 'Lusha',
    website: 'lusha.com',
    category: 'recruitment',
    region: 'Global',
    dataCollected: ['name', 'email', 'phone', 'employer', 'job_title'],
    sources: ['users', 'public_profiles', 'business_directories'],
    optOut: {
      available: true,
      url: 'https://www.lusha.com/opt-out',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 7,
      gdprCompliant: true,
      instructions: [
        'Opt-out-Formular ausfüllen',
        'Email bestätigen'
      ]
    },
    riskLevel: 'medium',
    description: 'Kontaktdaten-Enrichment für Sales.'
  },
  {
    id: 'hunter',
    name: 'Hunter.io',
    website: 'hunter.io',
    category: 'recruitment',
    region: 'Global',
    dataCollected: ['name', 'email', 'employer', 'job_title'],
    sources: ['websites', 'email_patterns'],
    optOut: {
      available: true,
      url: 'https://hunter.io/claim',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: true,
      instructions: [
        'Email suchen',
        'Claim/Remove wählen',
        'Verifizieren'
      ]
    },
    riskLevel: 'low',
    description: 'Email-Finder für Business-Kontakte.'
  },
  {
    id: 'clearbit',
    name: 'Clearbit',
    website: 'clearbit.com',
    category: 'marketing_data',
    region: 'Global',
    dataCollected: ['name', 'email', 'employer', 'job_title', 'social_profiles', 'company_info'],
    sources: ['websites', 'social_media', 'public_data'],
    optOut: {
      available: true,
      url: 'https://dashboard.clearbit.com/claim',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 7,
      gdprCompliant: true,
      instructions: [
        'Email eingeben',
        'Claim oder Delete wählen',
        'Per Email bestätigen'
      ]
    },
    riskLevel: 'medium',
    description: 'Data-Enrichment-Plattform für Marketing.'
  },
  // EU-specific
  {
    id: 'infobel',
    name: 'Infobel',
    website: 'infobel.com',
    category: 'people_search',
    region: 'EU',
    dataCollected: ['name', 'address', 'phone'],
    sources: ['phone_directories', 'business_registries'],
    optOut: {
      available: true,
      url: 'https://www.infobel.com/en/world/contact',
      method: 'email',
      requiresId: false,
      difficulty: 'medium',
      estimatedDays: 14,
      gdprCompliant: true,
      instructions: [
        'Email an contact senden',
        'DSGVO-Löschung beantragen'
      ]
    },
    riskLevel: 'medium',
    description: 'Europäisches Telefonverzeichnis.'
  },
  {
    id: 'dasoertliche',
    name: 'Das Örtliche',
    website: 'dasoertliche.de',
    category: 'people_search',
    region: 'EU',
    dataCollected: ['name', 'address', 'phone'],
    sources: ['phone_directories'],
    optOut: {
      available: true,
      url: 'https://www.dasoertliche.de/datenschutz',
      method: 'mail',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 14,
      gdprCompliant: true,
      instructions: [
        'Telefonanbieter kontaktieren',
        'Eintrag sperren lassen'
      ]
    },
    riskLevel: 'low',
    description: 'Deutsches Telefonbuch. Löschung über Telefonanbieter.'
  },
  {
    id: 'klicktel',
    name: 'Klicktel',
    website: 'klicktel.de',
    category: 'people_search',
    region: 'EU',
    dataCollected: ['name', 'address', 'phone'],
    sources: ['phone_directories'],
    optOut: {
      available: true,
      url: 'https://www.klicktel.de/datenschutz',
      method: 'mail',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 14,
      gdprCompliant: true,
      instructions: [
        'Telefonanbieter kontaktieren',
        'Oder DSGVO-Anfrage stellen'
      ]
    },
    riskLevel: 'low',
    description: 'Deutsches Telefonverzeichnis.'
  },
  {
    id: 'pagesjaunes',
    name: 'Pages Jaunes',
    website: 'pagesjaunes.fr',
    category: 'people_search',
    region: 'EU',
    dataCollected: ['name', 'address', 'phone'],
    sources: ['phone_directories'],
    optOut: {
      available: true,
      url: 'https://www.pagesjaunes.fr/infoslegales/viePrivee',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 14,
      gdprCompliant: true,
      instructions: [
        'Online-Formular nutzen',
        'DSGVO-Anfrage möglich'
      ]
    },
    riskLevel: 'low',
    description: 'Französisches Telefonverzeichnis.'
  },
  // Additional global brokers
  {
    id: 'peoplefinders',
    name: 'PeopleFinders',
    website: 'peoplefinders.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'age', 'relatives', 'property'],
    sources: ['public_records', 'property_records'],
    optOut: {
      available: true,
      url: 'https://www.peoplefinders.com/manage',
      method: 'web_form',
      requiresId: false,
      difficulty: 'medium',
      estimatedDays: 5,
      gdprCompliant: false,
      instructions: [
        'Manage-Seite besuchen',
        'Profil suchen und entfernen'
      ]
    },
    riskLevel: 'high',
    description: 'Umfassender Personensuchdienst.'
  },
  {
    id: 'mylife',
    name: 'MyLife',
    website: 'mylife.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'reputation_score', 'court_records'],
    sources: ['public_records', 'user_reviews', 'social_media'],
    optOut: {
      available: true,
      url: 'https://www.mylife.com/privacy-policy',
      method: 'phone',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 14,
      gdprCompliant: false,
      instructions: [
        'Telefonisch Kontakt aufnehmen',
        'ID-Verifizierung erforderlich',
        'Kann hartnäckig sein'
      ]
    },
    riskLevel: 'high',
    description: 'Reputation-Score-Dienst - schwieriges Opt-out.'
  },
  {
    id: 'thatsthem',
    name: 'ThatsThem',
    website: 'thatsthem.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'ip_address'],
    sources: ['public_records', 'marketing_lists'],
    optOut: {
      available: true,
      url: 'https://thatsthem.com/optout',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: false,
      instructions: [
        'Opt-out-Formular ausfüllen',
        'Email bestätigen'
      ]
    },
    riskLevel: 'medium',
    description: 'Kostenloser Personensuchdienst.'
  },
  {
    id: 'nuwber',
    name: 'Nuwber',
    website: 'nuwber.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'relatives', 'employment'],
    sources: ['public_records', 'social_media'],
    optOut: {
      available: true,
      url: 'https://nuwber.com/removal/link',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: false,
      instructions: [
        'Profil-URL kopieren',
        'Removal-Link anklicken'
      ]
    },
    riskLevel: 'high',
    description: 'Umfassender Personensuchdienst.'
  },
  {
    id: 'addresses',
    name: 'Addresses.com',
    website: 'addresses.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone'],
    sources: ['public_records', 'phone_directories'],
    optOut: {
      available: true,
      url: 'https://www.addresses.com/optout.php',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: false,
      instructions: [
        'Profil suchen',
        'Opt-out wählen'
      ]
    },
    riskLevel: 'medium',
    description: 'Adress-basierter Personensuchdienst.'
  },
  {
    id: 'publicrecordsnow',
    name: 'PublicRecordsNow',
    website: 'publicrecordsnow.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'court_records'],
    sources: ['public_records', 'court_records'],
    optOut: {
      available: true,
      url: 'https://www.publicrecordsnow.com/static/view/optout',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 5,
      gdprCompliant: false,
      instructions: [
        'Formular ausfüllen',
        'Bestätigen'
      ]
    },
    riskLevel: 'medium',
    description: 'Public Records Aggregator.'
  },
  {
    id: 'voterrecords',
    name: 'VoterRecords',
    website: 'voterrecords.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'party_affiliation', 'voting_history'],
    sources: ['voter_registration'],
    optOut: {
      available: true,
      url: 'https://voterrecords.com/optout',
      method: 'web_form',
      requiresId: false,
      difficulty: 'easy',
      estimatedDays: 3,
      gdprCompliant: false,
      instructions: [
        'Profil suchen',
        'Opt-out beantragen'
      ]
    },
    riskLevel: 'medium',
    description: 'Wählerregistrierungs-Daten.'
  },
  {
    id: 'ussearch',
    name: 'US Search',
    website: 'ussearch.com',
    category: 'people_search',
    region: 'US',
    dataCollected: ['name', 'address', 'phone', 'email', 'criminal_records'],
    sources: ['public_records'],
    optOut: {
      available: true,
      url: 'https://www.ussearch.com/opt-out/submit',
      method: 'web_form',
      requiresId: false,
      difficulty: 'medium',
      estimatedDays: 7,
      gdprCompliant: false,
      instructions: [
        'Opt-out-Formular ausfüllen',
        'Email verifizieren'
      ]
    },
    riskLevel: 'high',
    description: 'Umfassender Personensuchdienst.'
  },
  // Insurance
  {
    id: 'lexisnexis_clue',
    name: 'LexisNexis C.L.U.E.',
    website: 'personalreports.lexisnexis.com',
    category: 'insurance',
    region: 'US',
    dataCollected: ['name', 'insurance_claims', 'property_damage', 'auto_accidents'],
    sources: ['insurance_companies'],
    optOut: {
      available: false,
      url: 'https://consumer.risk.lexisnexis.com/request',
      method: 'mail',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 30,
      gdprCompliant: false,
      instructions: [
        'Kostenlose Auskunft anfordern',
        'Fehler korrigieren lassen',
        'Kein vollständiges Opt-out'
      ]
    },
    riskLevel: 'high',
    description: 'Versicherungs-Schadenshistorie. Beeinflusst Prämien.'
  },
  {
    id: 'verisk',
    name: 'Verisk/ISO',
    website: 'verisk.com',
    category: 'insurance',
    region: 'US',
    dataCollected: ['name', 'insurance_claims', 'property_info', 'driving_history'],
    sources: ['insurance_companies', 'dmv'],
    optOut: {
      available: false,
      url: 'https://www.verisk.com/privacy',
      method: 'mail',
      requiresId: true,
      difficulty: 'hard',
      estimatedDays: 30,
      gdprCompliant: false,
      instructions: [
        'Auskunft anfordern',
        'Fehler korrigieren',
        'Kein Opt-out möglich'
      ]
    },
    riskLevel: 'high',
    description: 'Versicherungs-Datenanalyse.'
  }
];

// Social media platforms configuration
const SOCIAL_PLATFORMS = [
  {
    id: 'twitter',
    displayName: 'Twitter/X',
    domain: 'twitter.com',
    alternativeDomains: ['x.com'],
    usernameFormat: '@{username}',
    profileUrl: 'https://twitter.com/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'bio', 'location', 'website', 'profile_image', 'followers', 'following'],
    privacySettings: ['protected_tweets', 'hide_location', 'private_likes'],
    riskLevel: 'medium'
  },
  {
    id: 'facebook',
    displayName: 'Facebook',
    domain: 'facebook.com',
    usernameFormat: '{username}',
    profileUrl: 'https://www.facebook.com/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'photo', 'location', 'workplace', 'education', 'relationship'],
    privacySettings: ['profile_lock', 'friend_list', 'post_visibility'],
    riskLevel: 'high'
  },
  {
    id: 'instagram',
    displayName: 'Instagram',
    domain: 'instagram.com',
    usernameFormat: '@{username}',
    profileUrl: 'https://www.instagram.com/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'bio', 'profile_image', 'posts', 'followers', 'following'],
    privacySettings: ['private_account', 'activity_status', 'story_sharing'],
    riskLevel: 'medium'
  },
  {
    id: 'linkedin',
    displayName: 'LinkedIn',
    domain: 'linkedin.com',
    usernameFormat: '{username}',
    profileUrl: 'https://www.linkedin.com/in/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'photo', 'headline', 'location', 'experience', 'education', 'connections'],
    privacySettings: ['profile_visibility', 'connection_visibility', 'activity_broadcast'],
    riskLevel: 'high'
  },
  {
    id: 'github',
    displayName: 'GitHub',
    domain: 'github.com',
    usernameFormat: '{username}',
    profileUrl: 'https://github.com/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'email', 'company', 'location', 'bio', 'repositories', 'contributions'],
    privacySettings: ['email_visibility', 'profile_readme'],
    riskLevel: 'medium'
  },
  {
    id: 'tiktok',
    displayName: 'TikTok',
    domain: 'tiktok.com',
    usernameFormat: '@{username}',
    profileUrl: 'https://www.tiktok.com/@{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'bio', 'profile_image', 'videos', 'followers', 'following'],
    privacySettings: ['private_account', 'who_can_duet', 'who_can_comment'],
    riskLevel: 'medium'
  },
  {
    id: 'youtube',
    displayName: 'YouTube',
    domain: 'youtube.com',
    usernameFormat: '@{username}',
    profileUrl: 'https://www.youtube.com/@{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'description', 'subscribers', 'videos', 'playlists'],
    privacySettings: ['subscription_visibility', 'liked_videos'],
    riskLevel: 'low'
  },
  {
    id: 'reddit',
    displayName: 'Reddit',
    domain: 'reddit.com',
    usernameFormat: 'u/{username}',
    profileUrl: 'https://www.reddit.com/user/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['karma', 'posts', 'comments', 'communities'],
    privacySettings: ['show_presence', 'allow_followers'],
    riskLevel: 'medium'
  },
  {
    id: 'pinterest',
    displayName: 'Pinterest',
    domain: 'pinterest.com',
    usernameFormat: '{username}',
    profileUrl: 'https://www.pinterest.com/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'bio', 'boards', 'pins', 'followers'],
    privacySettings: ['search_privacy', 'personalization'],
    riskLevel: 'low'
  },
  {
    id: 'snapchat',
    displayName: 'Snapchat',
    domain: 'snapchat.com',
    usernameFormat: '{username}',
    profileUrl: 'https://www.snapchat.com/add/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['display_name', 'bitmoji'],
    privacySettings: ['who_can_contact', 'who_can_view_story', 'show_in_quick_add'],
    riskLevel: 'medium'
  },
  {
    id: 'discord',
    displayName: 'Discord',
    domain: 'discord.com',
    usernameFormat: '{username}',
    checkMethod: 'none',
    publicDataFields: ['username', 'avatar', 'status'],
    privacySettings: ['who_can_dm', 'server_privacy'],
    riskLevel: 'low'
  },
  {
    id: 'telegram',
    displayName: 'Telegram',
    domain: 'telegram.org',
    usernameFormat: '@{username}',
    profileUrl: 'https://t.me/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'bio', 'photo'],
    privacySettings: ['phone_visibility', 'last_seen', 'who_can_forward'],
    riskLevel: 'low'
  },
  {
    id: 'medium',
    displayName: 'Medium',
    domain: 'medium.com',
    usernameFormat: '@{username}',
    profileUrl: 'https://medium.com/@{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'bio', 'articles', 'followers'],
    privacySettings: ['email_visibility'],
    riskLevel: 'low'
  },
  {
    id: 'twitch',
    displayName: 'Twitch',
    domain: 'twitch.tv',
    usernameFormat: '{username}',
    profileUrl: 'https://www.twitch.tv/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'bio', 'followers', 'streams'],
    privacySettings: ['whisper_settings', 'blocked_terms'],
    riskLevel: 'low'
  },
  {
    id: 'xing',
    displayName: 'XING',
    domain: 'xing.com',
    usernameFormat: '{username}',
    profileUrl: 'https://www.xing.com/profile/{username}',
    checkMethod: 'url_check',
    publicDataFields: ['name', 'photo', 'headline', 'location', 'experience'],
    privacySettings: ['profile_visibility', 'activity_visibility'],
    riskLevel: 'medium'
  }
];

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

// ===========================================
// Phase 10: Smart Privacy Coach
// ===========================================

// Privacy Coach Sessions (in-memory storage)
const coachSessions = new Map();
const SESSION_TTL = 60 * 60 * 1000; // 1 hour
const coachFeedback = [];

// Coach Knowledge Base - Privacy Terms
const PRIVACY_TERMS = {
  'k-anonymity': {
    simple: 'k-Anonymität bedeutet: Du bist in einer Gruppe von mindestens k Personen versteckt, die alle gleich aussehen. Je größer k, desto besser versteckt bist du.',
    detailed: 'k-Anonymität ist ein Datenschutz-Konzept, das sicherstellt, dass jede Person in einem Datensatz nicht von mindestens k-1 anderen Personen unterschieden werden kann. Dies wird erreicht, indem quasi-identifizierende Attribute (wie Alter, PLZ, Geschlecht) so verallgemeinert werden, dass mindestens k Personen identische Werte haben.',
    technical: 'Formal: Ein Datensatz erfüllt k-Anonymität, wenn für jeden Datensatz im Release mindestens k-1 andere Datensätze existieren, die in allen quasi-identifizierenden Attributen übereinstimmen. Das Schutzmodell wurde 2002 von Latanya Sweeney eingeführt und adressiert Linking-Angriffe auf veröffentlichte Daten.'
  },
  'l-diversity': {
    simple: 'l-Diversität erweitert k-Anonymität: Nicht nur musst du in einer Gruppe versteckt sein, sondern diese Gruppe muss auch verschiedene sensible Werte haben.',
    detailed: 'l-Diversität ist eine Erweiterung von k-Anonymität, die fordert, dass jede Äquivalenzklasse mindestens l verschiedene Werte für sensible Attribute enthält. Dies schützt vor Homogenitäts-Angriffen, bei denen alle Personen in einer k-anonymen Gruppe denselben sensiblen Wert haben.',
    technical: 'Ein Datensatz erfüllt l-Diversität, wenn für jede Äquivalenzklasse die Entropie der sensiblen Attribute mindestens log(l) beträgt, oder alternativ mindestens l verschiedene sensible Werte existieren.'
  },
  'differential-privacy': {
    simple: 'Differentielle Privatsphäre fügt mathematisch kontrollierten Zufall hinzu, sodass niemand sicher sagen kann, ob du in den Daten bist oder nicht.',
    detailed: 'Differentielle Privatsphäre ist ein mathematisches Framework, das garantiert, dass die Anwesenheit oder Abwesenheit einer einzelnen Person in einem Datensatz die Ergebnisse einer Analyse nur minimal beeinflusst. Dies wird durch Hinzufügen von kalibriertem Rauschen erreicht.',
    technical: 'Ein randomisierter Algorithmus M erfüllt ε-differentielle Privatsphäre, wenn für alle Datensätze D1, D2, die sich in höchstens einem Element unterscheiden, und für alle Ergebnismengen S gilt: P[M(D1) ∈ S] ≤ exp(ε) × P[M(D2) ∈ S].'
  },
  'pii': {
    simple: 'PII (Personally Identifiable Information) sind alle Daten, die dich direkt oder indirekt identifizieren können - von deinem Namen bis zu deiner IP-Adresse.',
    detailed: 'Personenbezogene Daten (PII) umfassen alle Informationen, die sich auf eine identifizierte oder identifizierbare Person beziehen. Dazu gehören direkte Identifikatoren (Name, Sozialversicherungsnummer) und quasi-identifizierende Attribute, die in Kombination zur Identifikation führen können.',
    technical: 'Nach DSGVO Art. 4: Personenbezogene Daten sind alle Informationen, die sich auf eine identifizierte oder identifizierbare natürliche Person beziehen. Eine Person ist identifizierbar, wenn sie direkt oder indirekt durch Zuordnung zu einer Kennung identifiziert werden kann.'
  },
  'gdpr': {
    simple: 'Die DSGVO ist das EU-Datenschutzgesetz, das dir Kontrolle über deine Daten gibt - du kannst sie einsehen, korrigieren und löschen lassen.',
    detailed: 'Die Datenschutz-Grundverordnung (DSGVO/GDPR) ist seit 2018 das zentrale EU-Datenschutzrecht. Sie gibt Bürgern Rechte wie Auskunft, Berichtigung, Löschung und Datenportabilität und verpflichtet Unternehmen zu Transparenz, Zweckbindung und Datensparsamkeit.',
    technical: 'Die DSGVO (Verordnung (EU) 2016/679) definiert sechs Rechtsgrundlagen für die Datenverarbeitung (Art. 6), etabliert Betroffenenrechte (Art. 12-23), fordert Privacy by Design/Default (Art. 25) und ermöglicht Bußgelder bis 4% des weltweiten Jahresumsatzes.'
  },
  'phishing': {
    simple: 'Phishing ist wie Angeln nach deinen Daten - Betrüger locken dich mit gefälschten E-Mails oder Websites, um Passwörter oder Bankdaten zu stehlen.',
    detailed: 'Phishing ist eine Cyberangriffsmethode, bei der Angreifer sich als vertrauenswürdige Entität ausgeben, um Opfer zur Preisgabe sensibler Daten zu verleiten. Varianten sind Spear-Phishing (gezielte Angriffe), Whaling (auf Führungskräfte), und Smishing (per SMS).',
    technical: 'Phishing-Angriffe nutzen Social Engineering und technische Täuschung (Domain-Spoofing, IDN-Homograph-Attacken, SSL-Strip). Moderne Phishing-Kits umfassen Echtzeit-Proxy-Techniken für MFA-Bypass und nutzen Adversary-in-the-Middle (AitM) Methoden.'
  },
  'deanonymization': {
    simple: 'Deanonymisierung bedeutet: Aus angeblich anonymen Daten kann man herausfinden, wer du bist - oft reichen wenige Datenpunkte.',
    detailed: 'Deanonymisierung ist der Prozess, bei dem anonymisierte Daten mit externen Informationen verknüpft werden, um Individuen zu identifizieren. Studien zeigen, dass 87% der US-Bevölkerung allein durch PLZ, Geburtsdatum und Geschlecht identifizierbar sind.',
    technical: 'Re-Identifikationsangriffe nutzen Techniken wie Linkage-Attacks (Narayanan/Shmatikov 2008), Inferenz-Angriffe auf ML-Modelle, oder Timing-Side-Channels. Selbst aggregierte oder verrauschte Daten können durch Auxiliary-Information-Angriffe kompromittiert werden.'
  },
  'identity-theft': {
    simple: 'Identitätsdiebstahl ist, wenn jemand deine persönlichen Daten nutzt, um sich als du auszugeben - zum Beispiel um Kredite aufzunehmen oder Verträge zu schließen.',
    detailed: 'Identitätsdiebstahl umfasst das Sammeln und Missbrauchen persönlicher Daten für Betrug. Dies kann zu finanziellen Schäden, Kreditproblemen und rechtlichen Komplikationen führen. Häufige Quellen sind Datenlecks, Phishing und Social Engineering.',
    technical: 'Identitätsbetrug wird kategorisiert in Account Takeover (Übernahme existierender Konten), Synthetic Identity Fraud (Kombination echter und erfundener Daten) und True Name Fraud (vollständige Identitätsübernahme). Präventionsmaßnahmen umfassen MFA, Kreditsperre und Dark Web Monitoring.'
  },
  '2fa': {
    simple: 'Zwei-Faktor-Authentifizierung (2FA) bedeutet: Neben dem Passwort brauchst du noch etwas Zweites - wie einen Code auf dem Handy. Doppelte Sicherheit!',
    detailed: '2FA fügt eine zweite Sicherheitsebene hinzu, die auf etwas basiert, das du weißt (Passwort), hast (Smartphone) oder bist (Fingerabdruck). Selbst wenn das Passwort gestohlen wird, schützt der zweite Faktor das Konto.',
    technical: 'MFA-Methoden umfassen TOTP (RFC 6238), HOTP (RFC 4226), WebAuthn/FIDO2 (hardwarebasiert), SMS-OTP (unsicher wegen SIM-Swapping) und Push-Benachrichtigungen. Hardware-Token wie YubiKey bieten den stärksten Schutz gegen Phishing.'
  }
};

// Coach Topics Database
const COACH_TOPICS = {
  categories: [
    {
      id: 'basics',
      name: 'Grundlagen',
      icon: '📚',
      topics: [
        {
          id: 'what_is_privacy',
          title: 'Was ist Datenschutz?',
          description: 'Die Grundlagen verstehen',
          difficulty: 'beginner',
          duration: '5 min',
          icon: '🔒'
        },
        {
          id: 'gdpr_basics',
          title: 'DSGVO einfach erklärt',
          description: 'Deine Rechte in der EU',
          difficulty: 'beginner',
          duration: '10 min',
          icon: '🇪🇺'
        },
        {
          id: 'data_minimization',
          title: 'Datensparsamkeit',
          description: 'Warum weniger mehr ist',
          difficulty: 'beginner',
          duration: '5 min',
          icon: '📉'
        }
      ]
    },
    {
      id: 'data_types',
      name: 'Datentypen',
      icon: '📊',
      topics: [
        {
          id: 'pii_explained',
          title: 'Persönliche Daten (PII)',
          description: 'Was sind personenbezogene Daten?',
          difficulty: 'beginner',
          duration: '7 min',
          icon: '👤'
        },
        {
          id: 'financial_data',
          title: 'Finanzdaten schützen',
          description: 'IBAN, Kreditkarte & Co',
          difficulty: 'intermediate',
          duration: '12 min',
          icon: '💳'
        },
        {
          id: 'health_data',
          title: 'Gesundheitsdaten',
          description: 'Besonders sensible Informationen',
          difficulty: 'intermediate',
          duration: '10 min',
          icon: '🏥'
        },
        {
          id: 'location_data',
          title: 'Standortdaten',
          description: 'GPS, Check-ins und mehr',
          difficulty: 'beginner',
          duration: '8 min',
          icon: '📍'
        }
      ]
    },
    {
      id: 'threats',
      name: 'Bedrohungen',
      icon: '⚠️',
      topics: [
        {
          id: 'phishing',
          title: 'Phishing erkennen',
          description: 'Betrügerische Nachrichten entlarven',
          difficulty: 'beginner',
          duration: '8 min',
          icon: '🎣'
        },
        {
          id: 'identity_theft',
          title: 'Identitätsdiebstahl',
          description: 'Wie Kriminelle deine Identität stehlen',
          difficulty: 'intermediate',
          duration: '15 min',
          icon: '🎭'
        },
        {
          id: 'deanonymization',
          title: 'Deanonymisierung',
          description: 'Wie man aus anonymen Daten Personen erkennt',
          difficulty: 'advanced',
          duration: '20 min',
          icon: '🔍'
        },
        {
          id: 'social_engineering',
          title: 'Social Engineering',
          description: 'Psychologische Manipulation erkennen',
          difficulty: 'intermediate',
          duration: '12 min',
          icon: '🧠'
        },
        {
          id: 'data_breaches',
          title: 'Datenlecks',
          description: 'Wenn Unternehmen Daten verlieren',
          difficulty: 'beginner',
          duration: '10 min',
          icon: '💧'
        }
      ]
    },
    {
      id: 'protection',
      name: 'Schutzmaßnahmen',
      icon: '🛡️',
      topics: [
        {
          id: 'password_security',
          title: 'Sichere Passwörter',
          description: 'Passwort-Manager und 2FA',
          difficulty: 'beginner',
          duration: '10 min',
          icon: '🔑'
        },
        {
          id: 'social_media_privacy',
          title: 'Social Media Einstellungen',
          description: 'Facebook, Instagram & Co absichern',
          difficulty: 'intermediate',
          duration: '15 min',
          icon: '📱'
        },
        {
          id: 'browser_privacy',
          title: 'Browser-Privatsphäre',
          description: 'Tracking verhindern',
          difficulty: 'intermediate',
          duration: '12 min',
          icon: '🌐'
        },
        {
          id: 'email_security',
          title: 'E-Mail-Sicherheit',
          description: 'Sichere Kommunikation',
          difficulty: 'beginner',
          duration: '8 min',
          icon: '📧'
        }
      ]
    },
    {
      id: 'advanced',
      name: 'Fortgeschritten',
      icon: '🎓',
      topics: [
        {
          id: 'anonymization_techniques',
          title: 'Anonymisierungstechniken',
          description: 'k-Anonymität, l-Diversität & mehr',
          difficulty: 'advanced',
          duration: '25 min',
          icon: '🔬'
        },
        {
          id: 'encryption_basics',
          title: 'Verschlüsselung verstehen',
          description: 'Wie Kryptografie schützt',
          difficulty: 'advanced',
          duration: '20 min',
          icon: '🔐'
        },
        {
          id: 'privacy_laws',
          title: 'Datenschutzgesetze weltweit',
          description: 'DSGVO, CCPA, LGPD & mehr',
          difficulty: 'advanced',
          duration: '30 min',
          icon: '⚖️'
        }
      ]
    }
  ]
};

// Topic Content Database
const TOPIC_CONTENT = {
  'phishing': {
    introduction: 'Phishing ist eine der häufigsten Betrugsmaschen im Internet. Betrüger versuchen, dich mit gefälschten E-Mails oder Websites zur Preisgabe sensibler Daten zu verleiten.',
    sections: [
      {
        title: 'Was ist Phishing?',
        content: 'Phishing kommt vom englischen "fishing" (Angeln). Genau wie beim Angeln werfen Betrüger einen "Köder" aus - meist in Form einer E-Mail oder Nachricht - und hoffen, dass du "anbeißt" und deine Daten preisgibst.',
        visualAid: {
          type: 'diagram',
          description: 'Betrüger → Gefälschte E-Mail → Opfer → Datendiebstahl'
        }
      },
      {
        title: 'Typische Merkmale',
        content: 'So erkennst du Phishing-Versuche:',
        bulletPoints: [
          'Dringlichkeit: "Ihr Konto wird gesperrt!"',
          'Rechtschreibfehler und seltsame Formulierungen',
          'Verdächtige Absender-Adressen (z.B. support@bank-sicherheit.com statt @bank.de)',
          'Links zu falschen Websites (Hover über Link zeigt andere URL)',
          'Aufforderung zur Dateneingabe per E-Mail',
          'Unpersönliche Anrede ("Sehr geehrter Kunde")'
        ]
      },
      {
        title: 'Arten von Phishing',
        content: 'Es gibt verschiedene Phishing-Varianten:',
        bulletPoints: [
          'E-Mail-Phishing: Massenhaft versendete betrügerische E-Mails',
          'Spear-Phishing: Gezielte Angriffe mit persönlichen Informationen',
          'Whaling: Angriffe auf Führungskräfte',
          'Smishing: Phishing per SMS',
          'Vishing: Phishing per Telefon'
        ]
      },
      {
        title: 'Praxis-Check',
        type: 'interactive',
        quiz: [
          {
            question: 'Diese Mail behauptet von deiner Bank zu sein. Der Absender ist "service@sparkasse-sicherheit.com". Ist das verdächtig?',
            options: ['Ja, verdächtig', 'Nein, sieht legitim aus'],
            correct: 0,
            explanation: 'Echte Bank-Mails kommen von @sparkasse.de, nicht von Phantasie-Domains!'
          },
          {
            question: 'Du erhältst eine E-Mail: "Dringend! Ihr PayPal-Konto wird in 24 Stunden gesperrt. Klicken Sie hier zum Verifizieren." Was tust du?',
            options: ['Schnell auf den Link klicken', 'Direkt auf paypal.com gehen und dort einloggen'],
            correct: 1,
            explanation: 'Niemals auf Links in verdächtigen E-Mails klicken. Gehe immer direkt zur offiziellen Website.'
          }
        ]
      }
    ],
    keyTakeaways: [
      'Nie auf Links in verdächtigen Mails klicken',
      'Absender-Adresse genau prüfen',
      'Bei Dringlichkeit besonders vorsichtig sein',
      'Im Zweifel: Unternehmen direkt kontaktieren'
    ],
    relatedTopics: ['identity_theft', 'password_security', 'email_security']
  },
  'password_security': {
    introduction: 'Sichere Passwörter sind deine erste Verteidigungslinie gegen Hacker. Doch was macht ein Passwort wirklich sicher?',
    sections: [
      {
        title: 'Was macht ein sicheres Passwort aus?',
        content: 'Ein sicheres Passwort sollte:',
        bulletPoints: [
          'Mindestens 12 Zeichen lang sein',
          'Groß- und Kleinbuchstaben enthalten',
          'Zahlen und Sonderzeichen nutzen',
          'Keine persönlichen Informationen (Geburtstag, Name) enthalten',
          'Nicht in Wörterbüchern vorkommen',
          'Für jeden Dienst einzigartig sein'
        ]
      },
      {
        title: 'Passwort-Manager',
        content: 'Ein Passwort-Manager speichert alle deine Passwörter sicher verschlüsselt. Du brauchst dir nur noch ein Master-Passwort zu merken.',
        bulletPoints: [
          'Empfohlen: Bitwarden (kostenlos, Open Source)',
          'Alternativ: 1Password, LastPass, KeePass',
          'Niemals Passwörter im Browser speichern',
          'Aktiviere 2FA für den Passwort-Manager'
        ]
      },
      {
        title: 'Zwei-Faktor-Authentifizierung (2FA)',
        content: '2FA fügt eine zweite Sicherheitsebene hinzu:',
        bulletPoints: [
          'Wissen: Dein Passwort',
          'Besitz: Dein Smartphone (Authenticator-App)',
          'Sein: Biometrie (Fingerabdruck, Gesicht)',
          'Hardware-Keys wie YubiKey bieten den besten Schutz'
        ]
      }
    ],
    keyTakeaways: [
      'Nutze einen Passwort-Manager',
      'Aktiviere 2FA überall wo möglich',
      'Jeder Account braucht ein einzigartiges Passwort',
      'Länge ist wichtiger als Komplexität'
    ],
    relatedTopics: ['phishing', 'identity_theft', '2fa']
  },
  'gdpr_basics': {
    introduction: 'Die DSGVO (Datenschutz-Grundverordnung) gibt dir als EU-Bürger starke Rechte über deine persönlichen Daten.',
    sections: [
      {
        title: 'Deine Rechte unter der DSGVO',
        content: 'Als EU-Bürger hast du folgende Rechte:',
        bulletPoints: [
          'Recht auf Auskunft: Erfahre, welche Daten ein Unternehmen über dich hat',
          'Recht auf Berichtigung: Falsche Daten korrigieren lassen',
          'Recht auf Löschung: "Recht auf Vergessenwerden"',
          'Recht auf Datenportabilität: Deine Daten in einem nutzbaren Format erhalten',
          'Recht auf Widerspruch: Der Datenverarbeitung widersprechen'
        ]
      },
      {
        title: 'Pflichten der Unternehmen',
        content: 'Unternehmen müssen:',
        bulletPoints: [
          'Transparent über Datenverarbeitung informieren',
          'Nur notwendige Daten erheben (Datensparsamkeit)',
          'Daten sicher aufbewahren',
          'Datenpannen innerhalb von 72 Stunden melden',
          'Auf deine Anfragen innerhalb eines Monats antworten'
        ]
      },
      {
        title: 'So nutzt du deine Rechte',
        content: 'Praktische Tipps zur Durchsetzung:',
        bulletPoints: [
          'Schreibe eine Auskunftsanfrage per E-Mail oder Brief',
          'Nutze Vorlagen von Verbraucherzentralen',
          'Setze eine Frist von 30 Tagen',
          'Bei Verstößen: Beschwerde bei der Datenschutzbehörde einreichen'
        ]
      }
    ],
    keyTakeaways: [
      'Du hast umfangreiche Rechte über deine Daten',
      'Unternehmen müssen innerhalb eines Monats antworten',
      'Bei Verstößen kannst du dich bei der Datenschutzbehörde beschweren',
      'Löschungen müssen auch bei Drittanbietern durchgeführt werden'
    ],
    relatedTopics: ['what_is_privacy', 'data_minimization', 'privacy_laws']
  },
  'identity_theft': {
    introduction: 'Identitätsdiebstahl ist, wenn jemand deine persönlichen Daten nutzt, um sich als du auszugeben - mit potenziell verheerenden Folgen.',
    sections: [
      {
        title: 'Wie Identitätsdiebstahl funktioniert',
        content: 'Kriminelle sammeln deine Daten aus verschiedenen Quellen:',
        bulletPoints: [
          'Datenlecks: Gehackte Websites verkaufen Daten im Darknet',
          'Phishing: Gefälschte E-Mails und Websites',
          'Social Engineering: Manipulation per Telefon',
          'Dumpster Diving: Durchsuchen von Müll nach Dokumenten',
          'Shoulder Surfing: Beobachten bei der Passworteingabe'
        ]
      },
      {
        title: 'Folgen von Identitätsdiebstahl',
        content: 'Die Konsequenzen können schwerwiegend sein:',
        bulletPoints: [
          'Finanzieller Schaden: Kredite in deinem Namen',
          'Rufschädigung: Fake-Accounts in sozialen Medien',
          'Rechtliche Probleme: Straftaten unter deiner Identität',
          'Emotionaler Stress: Angst und Hilflosigkeit',
          'Langwierige Aufklärung: Monate bis Jahre'
        ]
      },
      {
        title: 'Schutzmaßnahmen',
        content: 'So schützt du dich:',
        bulletPoints: [
          'Starke, einzigartige Passwörter mit 2FA',
          'Regelmäßige Überprüfung deiner Kontoauszüge',
          'Kreditauskunft regelmäßig prüfen (SCHUFA etc.)',
          'Vorsicht bei der Preisgabe persönlicher Daten',
          'Sichere Entsorgung von Dokumenten (Schredder)'
        ]
      }
    ],
    keyTakeaways: [
      'Teile persönliche Daten nur wenn nötig',
      'Überwache regelmäßig deine Finanzen',
      'Reagiere sofort bei Verdacht',
      'Erstatte Anzeige und informiere Betroffene'
    ],
    relatedTopics: ['phishing', 'password_security', 'data_breaches']
  },
  'pii_explained': {
    introduction: 'Personenbezogene Daten (PII - Personally Identifiable Information) sind alle Informationen, die dich direkt oder indirekt identifizieren können.',
    sections: [
      {
        title: 'Direkte Identifikatoren',
        content: 'Diese Daten identifizieren dich eindeutig:',
        bulletPoints: [
          'Vollständiger Name',
          'Sozialversicherungsnummer',
          'Personalausweisnummer',
          'Führerscheinnummer',
          'Biometrische Daten (Fingerabdruck, Gesicht)',
          'E-Mail-Adresse'
        ]
      },
      {
        title: 'Quasi-Identifikatoren',
        content: 'Diese Daten allein sind harmlos, aber in Kombination gefährlich:',
        bulletPoints: [
          'Geburtsdatum (grenzt auf ~0,3% der Bevölkerung ein)',
          'Postleitzahl (auf ~20.000 Personen)',
          'Geschlecht (auf ~50%)',
          'Beruf, Arbeitgeber, Schulbildung',
          'ZIP + Geburtsdatum + Geschlecht = 87% der US-Bürger eindeutig identifizierbar!'
        ]
      },
      {
        title: 'Sensible Daten',
        content: 'Besonders schützenswerte Kategorien:',
        bulletPoints: [
          'Gesundheitsdaten und medizinische Informationen',
          'Religiöse und politische Überzeugungen',
          'Sexuelle Orientierung',
          'Ethnische Herkunft',
          'Genetische Daten',
          'Biometrische Daten'
        ]
      }
    ],
    keyTakeaways: [
      'Auch "harmlose" Daten können in Kombination gefährlich sein',
      'Sensible Daten haben besonderen Schutz',
      'Teile nur Daten, die wirklich nötig sind',
      'Quasi-Identifikatoren sind oft unterschätzt'
    ],
    relatedTopics: ['deanonymization', 'data_minimization', 'gdpr_basics']
  },
  'deanonymization': {
    introduction: 'Deanonymisierung zeigt, dass "anonyme" Daten oft gar nicht so anonym sind, wie wir denken.',
    sections: [
      {
        title: 'Was ist Deanonymisierung?',
        content: 'Deanonymisierung ist der Prozess, bei dem scheinbar anonyme Daten mit anderen Informationen verknüpft werden, um Individuen zu identifizieren.',
        bulletPoints: [
          'Linkage-Attacken: Verbindung von Datensätzen',
          'Inferenz-Angriffe: Rückschlüsse aus Mustern',
          'Auxiliary Information: Nutzung externer Datenquellen',
          'Selbst aggregierte Daten können anfällig sein'
        ]
      },
      {
        title: 'Berühmte Fälle',
        content: 'Diese Beispiele zeigen die Gefahr:',
        bulletPoints: [
          'Netflix-Preis (2007): "Anonyme" Filmbewertungen mit IMDB verknüpft',
          'AOL-Suchanfragen (2006): User durch Suchmuster identifiziert',
          'NYC Taxi-Daten (2013): Promi-Fahrten durch Metadaten enthüllt',
          'Fitnesstracker (2018): Militärbasen durch Aktivitätsdaten aufgedeckt'
        ]
      },
      {
        title: 'Schutzmaßnahmen',
        content: 'Wie echte Anonymisierung funktioniert:',
        bulletPoints: [
          'k-Anonymität: Mindestens k Personen sind ununterscheidbar',
          'l-Diversität: Verschiedene sensible Werte pro Gruppe',
          'Differential Privacy: Mathematisch garantierter Schutz',
          'Aggregation mit Mindestgruppen-größe'
        ]
      }
    ],
    keyTakeaways: [
      'Anonymisierung ist schwieriger als gedacht',
      'Wenige Datenpunkte reichen oft zur Identifikation',
      'Veröffentlichte Daten können mit anderen Quellen verknüpft werden',
      'Echte Anonymisierung erfordert mathematische Garantien'
    ],
    relatedTopics: ['pii_explained', 'anonymization_techniques', 'data_breaches']
  }
};

// Risk Type Explanations for Coach
const RISK_TYPE_EXPLANATIONS = {
  email: {
    name: 'E-Mail-Adresse',
    icon: '📧',
    risks: [
      'Spam und Phishing-Angriffe',
      'Verknüpfung verschiedener Online-Konten',
      'Teil von Datenlecks',
      'Social Engineering'
    ],
    advice: [
      'Nutze verschiedene E-Mails für verschiedene Zwecke',
      'Vermeide die Haupt-E-Mail für unwichtige Services',
      'Prüfe regelmäßig auf Datenlecks (haveibeenpwned.com)'
    ],
    severity: 'medium'
  },
  phone: {
    name: 'Telefonnummer',
    icon: '📱',
    risks: [
      'SIM-Swapping-Angriffe',
      'Unerwünschte Anrufe und SMS',
      'Standortverfolgung',
      'Account-Übernahme bei SMS-2FA'
    ],
    advice: [
      'Gib die Nummer nur bei echtem Bedarf an',
      'Nutze App-basierte 2FA statt SMS',
      'Bei VoIP: Separate Nummer für Online-Dienste'
    ],
    severity: 'high'
  },
  iban: {
    name: 'IBAN',
    icon: '🏦',
    risks: [
      'Lastschriftbetrug',
      'Identitätsdiebstahl',
      'Phishing mit echten Kontodaten',
      'Wirtschaftsspionage'
    ],
    advice: [
      'IBAN nie öffentlich teilen',
      'Kontoauszüge regelmäßig prüfen',
      'Unbekannte Lastschriften sofort melden',
      'Lastschriften können 8 Wochen zurückgebucht werden'
    ],
    severity: 'critical'
  },
  credit_card: {
    name: 'Kreditkartennummer',
    icon: '💳',
    risks: [
      'Direkter finanzieller Missbrauch',
      'Online-Betrug',
      'Card-not-present Fraud',
      'Verkauf im Darknet'
    ],
    advice: [
      'Nur auf vertrauenswürdigen Websites eingeben',
      'Virtuelle Kreditkarten für Online-Shopping',
      'Benachrichtigungen für jede Transaktion aktivieren',
      'Bei Verdacht sofort sperren lassen'
    ],
    severity: 'critical'
  },
  address: {
    name: 'Wohnadresse',
    icon: '🏠',
    risks: [
      'Stalking und physische Bedrohungen',
      'Einbruchsgefahr bei Urlaubsankündigungen',
      'Identitätsdiebstahl',
      'Unerwünschte Post und Werbung'
    ],
    advice: [
      'Vollständige Adresse nur wenn nötig',
      '"München" statt vollständiger Anschrift',
      'Nie Adresse mit Urlaubsplänen kombinieren'
    ],
    severity: 'high'
  },
  birthdate: {
    name: 'Geburtsdatum',
    icon: '🎂',
    risks: [
      'Häufig als Sicherheitsfrage verwendet',
      'Teil von Identitätsdiebstahl-Datensätzen',
      'Ermöglicht Altersverifizierungs-Betrug',
      'Kombiniert mit anderen Daten: hohe Identifizierbarkeit'
    ],
    advice: [
      'Maximal Monat + Jahr teilen, nie den Tag',
      'Keine echten Daten für "Sicherheitsfragen"',
      'Vorsicht bei Geburtstags-Aktionen online'
    ],
    severity: 'medium'
  },
  full_name: {
    name: 'Vollständiger Name',
    icon: '👤',
    risks: [
      'Grundlage für Social Engineering',
      'Verknüpfung von Online-Profilen',
      'Ermöglicht gezielte Angriffe',
      'Teil jeder Identitätsprüfung'
    ],
    advice: [
      'Pseudonyme für nicht-offizielle Dienste',
      'Initialen oder Vorname nur bei Social Media',
      'Voller Name nur bei rechtlicher Notwendigkeit'
    ],
    severity: 'medium'
  },
  health: {
    name: 'Gesundheitsdaten',
    icon: '🏥',
    risks: [
      'Diskriminierung durch Arbeitgeber oder Versicherungen',
      'Erpressung',
      'Stigmatisierung',
      'Besonders schützenswert nach DSGVO'
    ],
    advice: [
      'Niemals öffentlich teilen',
      'Vorsicht bei Gesundheits-Apps',
      'Anonyme Foren für sensible Themen'
    ],
    severity: 'critical'
  },
  employer: {
    name: 'Arbeitgeber',
    icon: '🏢',
    risks: [
      'Spear-Phishing-Angriffe',
      'Social Engineering im Unternehmenskontext',
      'Wirtschaftsspionage',
      'Karriereschädigung bei kritischen Posts'
    ],
    advice: [
      'Allgemein bleiben: "Automobilbranche" statt "BMW"',
      'Keine internen Informationen teilen',
      'Kritik nur anonym äußern'
    ],
    severity: 'medium'
  },
  location: {
    name: 'Aktueller Standort',
    icon: '📍',
    risks: [
      'Stalking in Echtzeit',
      'Einbruch während Abwesenheit',
      'Bewegungsprofile erstellen',
      'Vorhersage zukünftiger Aufenthaltsorte'
    ],
    advice: [
      'Echtzeit-Standort nie öffentlich teilen',
      'Fotos erst nach Verlassen des Ortes posten',
      'GPS-Metadaten aus Fotos entfernen'
    ],
    severity: 'high'
  }
};

// Quick Tips Database
const QUICK_TIPS = [
  {
    id: 'tip_001',
    icon: '💡',
    title: 'Tipp des Tages',
    content: 'Verwende für jeden Dienst ein einzigartiges Passwort. Ein Passwort-Manager hilft dabei!',
    category: 'password_security'
  },
  {
    id: 'tip_002',
    icon: '🔒',
    title: 'Wusstest du?',
    content: 'In der EU hast du das Recht, deine Daten von jedem Unternehmen löschen zu lassen (DSGVO Art. 17).',
    category: 'gdpr'
  },
  {
    id: 'tip_003',
    icon: '⚠️',
    title: 'Achtung!',
    content: 'Mit nur Geburtsdatum, PLZ und Geschlecht sind 87% der Menschen eindeutig identifizierbar.',
    category: 'deanonymization'
  },
  {
    id: 'tip_004',
    icon: '📧',
    title: 'E-Mail-Tipp',
    content: 'Nutze Alias-Adressen (z.B. vorname+shop@email.de) um zu sehen, wer deine Daten weitergibt.',
    category: 'email_security'
  },
  {
    id: 'tip_005',
    icon: '🔐',
    title: '2FA aktivieren',
    content: 'Zwei-Faktor-Authentifizierung macht dein Konto 99% sicherer. Nutze Authenticator-Apps statt SMS!',
    category: '2fa'
  },
  {
    id: 'tip_006',
    icon: '🎣',
    title: 'Phishing-Schutz',
    content: 'Fahre immer mit der Maus über Links, bevor du klickst. Die echte URL wird unten im Browser angezeigt.',
    category: 'phishing'
  },
  {
    id: 'tip_007',
    icon: '📱',
    title: 'App-Berechtigungen',
    content: 'Prüfe regelmäßig, welche Apps Zugriff auf Kamera, Mikrofon und Standort haben.',
    category: 'mobile_security'
  },
  {
    id: 'tip_008',
    icon: '🌐',
    title: 'Browser-Privatsphäre',
    content: 'Nutze den privaten/inkognito Modus für sensible Suchen und lösche regelmäßig Cookies.',
    category: 'browser_privacy'
  },
  {
    id: 'tip_009',
    icon: '💳',
    title: 'Karten-Sicherheit',
    content: 'Aktiviere Push-Benachrichtigungen für jede Kreditkarten-Transaktion. So erkennst du Betrug sofort.',
    category: 'financial_data'
  },
  {
    id: 'tip_010',
    icon: '🗑️',
    title: 'Daten löschen',
    content: 'Lösche regelmäßig alte Accounts, die du nicht mehr nutzt. Weniger Daten = weniger Angriffsfläche.',
    category: 'data_minimization'
  }
];

// Daily Challenges
const DAILY_CHALLENGES = [
  {
    id: 'challenge_001',
    title: 'Passwort-Check',
    description: 'Ändere heute ein schwaches Passwort in ein starkes',
    reward: '+10 Privacy Score',
    difficulty: 'easy'
  },
  {
    id: 'challenge_002',
    title: '2FA aktivieren',
    description: 'Aktiviere Zwei-Faktor-Authentifizierung bei einem wichtigen Account',
    reward: '+20 Privacy Score',
    difficulty: 'easy'
  },
  {
    id: 'challenge_003',
    title: 'Social Media Check',
    description: 'Prüfe die Datenschutz-Einstellungen deines Lieblings-Social-Media-Accounts',
    reward: '+15 Privacy Score',
    difficulty: 'easy'
  },
  {
    id: 'challenge_004',
    title: 'Breach Check',
    description: 'Prüfe auf haveibeenpwned.com, ob deine E-Mail in einem Datenleck ist',
    reward: '+10 Privacy Score',
    difficulty: 'easy'
  },
  {
    id: 'challenge_005',
    title: 'App-Audit',
    description: 'Lösche 3 Apps, die du nicht mehr nutzt',
    reward: '+15 Privacy Score',
    difficulty: 'medium'
  }
];

// Coach Response Templates
const COACH_TEMPLATES = {
  greeting: {
    de: 'Hallo! 👋 Ich bin dein Privacy Coach. Ich helfe dir, deine Daten besser zu schützen.\n\nDu kannst mich alles über Datenschutz fragen, oder ich erkläre dir die Risiken deiner Texte.\n\nWomit kann ich dir heute helfen?',
    en: 'Hello! 👋 I\'m your Privacy Coach. I help you protect your data better.\n\nYou can ask me anything about privacy, or I\'ll explain the risks in your texts.\n\nHow can I help you today?'
  },
  unknown: {
    de: 'Das ist eine interessante Frage! Leider bin ich mir nicht ganz sicher, wie ich dir hier am besten helfen kann. Kannst du deine Frage anders formulieren oder mir mehr Kontext geben?',
    en: 'That\'s an interesting question! I\'m not quite sure how to best help you here. Could you rephrase your question or give me more context?'
  },
  riskHigh: {
    de: 'Achtung! 🚨 Dein Text enthält kritische Daten, die dich eindeutig identifizierbar machen.',
    en: 'Warning! 🚨 Your text contains critical data that makes you uniquely identifiable.'
  }
};

// Helper: Generate unique session ID
function generateSessionId() {
  return 'session_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
}

// Helper: Generate unique message ID
function generateMessageId() {
  return 'msg_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

// Helper: Cleanup expired sessions
function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [id, session] of coachSessions.entries()) {
    if (now - new Date(session.createdAt).getTime() > SESSION_TTL) {
      coachSessions.delete(id);
    }
  }
}

// Periodic session cleanup (every 15 minutes)
setInterval(cleanupExpiredSessions, 15 * 60 * 1000);

// Helper: Get or create session
function getOrCreateSession(sessionId, userProfile = {}) {
  if (sessionId && coachSessions.has(sessionId)) {
    const session = coachSessions.get(sessionId);
    session.lastActivity = new Date().toISOString();
    return session;
  }

  const newSession = {
    id: generateSessionId(),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SESSION_TTL).toISOString(),
    lastActivity: new Date().toISOString(),
    userProfile: {
      privacyLevel: userProfile.privacyLevel || 'beginner',
      language: userProfile.language || 'de',
      interests: userProfile.interests || []
    },
    conversationHistory: [],
    context: {
      lastAnalyzedText: null,
      lastAnalysisResults: null,
      topicsDiscussed: [],
      suggestedActions: []
    }
  };

  coachSessions.set(newSession.id, newSession);
  return newSession;
}

// Helper: Detect data types in text
function detectDataTypes(text) {
  const detected = [];

  // Email
  if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(text)) {
    const match = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    detected.push({ type: 'email', value: match[0], risk: 'medium' });
  }

  // IBAN
  if (/[A-Z]{2}\d{2}[\s]?(?:\d{4}[\s]?){4,7}\d{0,2}/.test(text)) {
    const match = text.match(/[A-Z]{2}\d{2}[\s]?(?:\d{4}[\s]?){4,7}\d{0,2}/);
    detected.push({ type: 'iban', value: match[0], risk: 'critical' });
  }

  // Phone (German format)
  if (/(?:\+49|0049|0)[\s]?(?:\d[\s]?){9,14}/.test(text)) {
    const match = text.match(/(?:\+49|0049|0)[\s]?(?:\d[\s]?){9,14}/);
    detected.push({ type: 'phone', value: match[0], risk: 'high' });
  }

  // Address (German format)
  if (/\b[\wäöüßÄÖÜ]+(?:straße|str\.|weg|gasse|platz|allee)\s+\d+/i.test(text)) {
    const match = text.match(/[\wäöüßÄÖÜ]+(?:straße|str\.|weg|gasse|platz|allee)\s+\d+[a-z]?(?:,?\s*\d{5}\s+[\wäöüßÄÖÜ]+)?/i);
    detected.push({ type: 'address', value: match ? match[0] : 'Adresse', risk: 'high' });
  }

  // German postal code with city
  if (/\b\d{5}\s+[A-ZÄÖÜa-zäöüß][a-zäöüß]+\b/.test(text)) {
    const match = text.match(/\d{5}\s+[A-ZÄÖÜa-zäöüß][a-zäöüß]+/);
    detected.push({ type: 'postal_code', value: match[0], risk: 'medium' });
  }

  // Birthdate
  if (/\b(\d{1,2}[./]\d{1,2}[./]\d{2,4}|\d{4}-\d{2}-\d{2})\b/.test(text)) {
    const match = text.match(/\d{1,2}[./]\d{1,2}[./]\d{2,4}|\d{4}-\d{2}-\d{2}/);
    detected.push({ type: 'birthdate', value: match[0], risk: 'medium' });
  }

  // Age
  if (/\b(\d{1,2})\s*(?:Jahre|J\.|years old|y\/o)\b/i.test(text)) {
    const match = text.match(/(\d{1,2})\s*(?:Jahre|J\.|years old|y\/o)/i);
    detected.push({ type: 'age', value: match[0], risk: 'low' });
  }

  // Credit card
  if (/\b(?:\d{4}[\s-]?){3}\d{4}\b/.test(text)) {
    const match = text.match(/(?:\d{4}[\s-]?){3}\d{4}/);
    detected.push({ type: 'credit_card', value: match[0].substring(0, 4) + ' **** **** ****', risk: 'critical' });
  }

  return detected;
}

// Helper: Calculate uniqueness contribution
function calculateUniquenessContribution(dataType) {
  const contributions = {
    full_name: 0.35,
    address: 0.45,
    birthdate: 0.15,
    age: 0.05,
    employer: 0.15,
    phone: 0.40,
    email: 0.30,
    iban: 0.25,
    credit_card: 0.20,
    postal_code: 0.10
  };
  return contributions[dataType] || 0.05;
}

// Helper: Generate coach response based on context
function generateCoachResponse(message, context, userProfile) {
  const lang = userProfile.language || 'de';
  const lowerMessage = message.toLowerCase();

  // Check for greetings
  if (/^(hallo|hi|hey|guten tag|servus|moin|hello)/i.test(lowerMessage)) {
    return {
      message: COACH_TEMPLATES.greeting[lang] || COACH_TEMPLATES.greeting.de,
      messageType: 'greeting',
      confidence: 1.0
    };
  }

  // Check for questions about specific data types
  for (const [type, info] of Object.entries(RISK_TYPE_EXPLANATIONS)) {
    if (lowerMessage.includes(type) || lowerMessage.includes(info.name.toLowerCase())) {
      const riskList = info.risks.map((r, i) => `${i + 1}. ${r}`).join('\n');
      const adviceList = info.advice.map(a => `- ${a}`).join('\n');

      return {
        message: `**${info.icon} ${info.name}**\n\n**Risiken:**\n${riskList}\n\n**Was du tun solltest:**\n${adviceList}`,
        messageType: 'explanation',
        confidence: 0.9,
        sources: [{ type: 'knowledge_base', topic: type }]
      };
    }
  }

  // Check for questions about privacy terms
  for (const [term, definitions] of Object.entries(PRIVACY_TERMS)) {
    const termVariants = [term, term.replace(/-/g, ' '), term.replace(/-/g, '')];
    if (termVariants.some(v => lowerMessage.includes(v))) {
      const complexity = userProfile.privacyLevel === 'advanced' ? 'technical' :
                        userProfile.privacyLevel === 'intermediate' ? 'detailed' : 'simple';

      return {
        message: `**${term.replace(/-/g, ' ').toUpperCase()}**\n\n${definitions[complexity]}`,
        messageType: 'explanation',
        confidence: 0.95,
        sources: [{ type: 'knowledge_base', topic: term }]
      };
    }
  }

  // Check for risk-related questions
  if (lowerMessage.includes('warum') && (lowerMessage.includes('gefährlich') || lowerMessage.includes('risiko') || lowerMessage.includes('schlecht'))) {
    // If we have previous analysis context
    if (context && context.previousAnalysis) {
      const risks = context.previousAnalysis.risks || [];
      if (risks.length > 0) {
        const riskType = risks[0];
        const riskInfo = RISK_TYPE_EXPLANATIONS[riskType];
        if (riskInfo) {
          return {
            message: `Diese Daten sind aus mehreren Gründen sensibel:\n\n**${riskInfo.icon} ${riskInfo.name}**\n\n` +
                    `**Risiken:**\n${riskInfo.risks.map((r, i) => `${i + 1}. **${r}**`).join('\n')}\n\n` +
                    `**Was du tun solltest:**\n${riskInfo.advice.map(a => `- ${a}`).join('\n')}`,
            messageType: 'explanation',
            confidence: 0.95,
            sources: [{ type: 'knowledge_base', topic: riskType }]
          };
        }
      }
    }
  }

  // Check for topic requests
  if (lowerMessage.includes('themen') || lowerMessage.includes('lernen') || lowerMessage.includes('topics')) {
    return {
      message: 'Ich kann dir viel über Datenschutz beibringen! Hier sind einige Themen:\n\n' +
              '📚 **Grundlagen**: Was ist Datenschutz, DSGVO erklärt\n' +
              '📊 **Datentypen**: Persönliche Daten, Finanzdaten, Gesundheitsdaten\n' +
              '⚠️ **Bedrohungen**: Phishing, Identitätsdiebstahl, Deanonymisierung\n' +
              '🛡️ **Schutzmaßnahmen**: Passwörter, 2FA, Social Media Einstellungen\n\n' +
              'Worüber möchtest du mehr erfahren?',
      messageType: 'menu',
      confidence: 0.9
    };
  }

  // Default response
  return {
    message: COACH_TEMPLATES.unknown[lang] || COACH_TEMPLATES.unknown.de,
    messageType: 'clarification',
    confidence: 0.5
  };
}

// ===========================================
// Phase 11: Privacy Templates
// ===========================================

// Template Categories
const TEMPLATE_CATEGORIES = [
  {
    id: 'social_media',
    name: 'Social Media',
    icon: '📱',
    description: 'Sichere Bio-Texte für Social Media Profile',
    subcategories: ['bio', 'posts', 'comments']
  },
  {
    id: 'job_application',
    name: 'Bewerbungen',
    icon: '💼',
    description: 'Datenschutzfreundliche Bewerbungstexte',
    subcategories: ['cover_letter', 'cv_summary', 'references']
  },
  {
    id: 'online_forms',
    name: 'Online-Formulare',
    icon: '📝',
    description: 'Minimale Angaben für Registrierungen',
    subcategories: ['registration', 'contact', 'surveys']
  },
  {
    id: 'email_responses',
    name: 'E-Mail Antworten',
    icon: '✉️',
    description: 'Ablehnungen von Datenanfragen',
    subcategories: ['data_requests', 'marketing_optout', 'consent_withdrawal']
  },
  {
    id: 'gdpr_requests',
    name: 'DSGVO-Anfragen',
    icon: '⚖️',
    description: 'Auskunfts- und Löschungsanfragen',
    subcategories: ['access', 'deletion', 'rectification', 'portability', 'objection']
  }
];

// Privacy Templates Database
const PRIVACY_TEMPLATES = [
  // Social Media Templates
  {
    id: 'sm_bio_minimal',
    name: 'Minimale Bio',
    category: 'social_media',
    subcategory: 'bio',
    description: 'Kurze Bio ohne persönliche Details',
    privacyScore: 95,
    popularity: 1250,
    tags: ['instagram', 'twitter', 'tiktok'],
    preview: 'Kreativ unterwegs | Kaffee-Enthusiast ☕',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_creative',
        name: 'Kreativ',
        content: 'Kreativ unterwegs | {{HOBBY}} {{EMOJI}} | Immer neugierig',
        tone: 'casual'
      },
      {
        id: 'variant_minimal',
        name: 'Ultra-Minimal',
        content: '{{EMOJI}} {{EMOJI}} {{EMOJI}}',
        tone: 'minimal'
      },
      {
        id: 'variant_mysterious',
        name: 'Geheimnisvoll',
        content: 'Manchmal hier, manchmal dort. Meist irgendwo dazwischen.',
        tone: 'mysterious'
      },
      {
        id: 'variant_interests',
        name: 'Interessen-fokussiert',
        content: '{{HOBBY}} | {{HOBBY2}} | {{EMOJI}}',
        tone: 'casual'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{HOBBY}}',
        description: 'Ein Hobby (ohne zu spezifisch zu sein)',
        examples: ['Musik', 'Kunst', 'Sport', 'Lesen', 'Fotografie', 'Gaming']
      },
      {
        key: '{{HOBBY2}}',
        description: 'Ein zweites Hobby',
        examples: ['Reisen', 'Kochen', 'Natur', 'Tech', 'Film']
      },
      {
        key: '{{EMOJI}}',
        description: 'Ein passendes Emoji',
        examples: ['🎨', '📚', '🎵', '⚡', '☕', '🌿', '📸']
      }
    ],
    tips: [
      'Vermeide deinen echten Namen',
      'Keine Altersangaben oder Geburtsdaten',
      'Standort nur sehr allgemein (Land, nicht Stadt)',
      'Arbeitgeber weglassen oder nur Branche nennen'
    ],
    doNot: [
      'Geburtsdatum teilen',
      'Genauen Wohnort angeben',
      'Arbeitgeber + Position nennen',
      'Familienstand erwähnen'
    ]
  },
  {
    id: 'sm_bio_professional',
    name: 'Professionelle Bio',
    category: 'social_media',
    subcategory: 'bio',
    description: 'Business-fokussiert ohne Privates',
    privacyScore: 88,
    popularity: 890,
    tags: ['linkedin', 'xing', 'twitter'],
    preview: 'Marketing | Digital Strategy | Speaker',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_expert',
        name: 'Experte',
        content: '{{BRANCHE}} | {{SKILL}} | {{SKILL2}}',
        tone: 'professional'
      },
      {
        id: 'variant_passion',
        name: 'Mit Leidenschaft',
        content: 'Leidenschaftlich für {{BRANCHE}} | {{SKILL}} Enthusiast',
        tone: 'professional'
      },
      {
        id: 'variant_helping',
        name: 'Hilfsbereit',
        content: 'Helfe bei {{SKILL}} | {{BRANCHE}} | Open for connections',
        tone: 'professional'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{BRANCHE}}',
        description: 'Deine Branche (allgemein)',
        examples: ['Marketing', 'Tech', 'Finance', 'Design', 'Consulting']
      },
      {
        key: '{{SKILL}}',
        description: 'Eine Fähigkeit',
        examples: ['Strategy', 'Analytics', 'Leadership', 'Innovation']
      },
      {
        key: '{{SKILL2}}',
        description: 'Eine weitere Fähigkeit',
        examples: ['Project Management', 'Team Building', 'Digital Transformation']
      }
    ],
    tips: [
      'Branche statt spezifischem Arbeitgeber',
      'Fähigkeiten statt Jobtitel',
      'Keine Jahreszahlen oder Erfahrungsdauer'
    ],
    doNot: [
      'Aktuellen Arbeitgeber nennen',
      'Genauen Jobtitel angeben',
      'Jahrelange Erfahrung mit Zahl nennen'
    ]
  },
  {
    id: 'sm_bio_dating',
    name: 'Dating-Profil Bio',
    category: 'social_media',
    subcategory: 'bio',
    description: 'Interessant ohne identifizierbar zu sein',
    privacyScore: 85,
    popularity: 720,
    tags: ['tinder', 'bumble', 'hinge'],
    preview: 'Suche jemanden für Kaffee und Gespräche ☕',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_casual',
        name: 'Locker',
        content: '{{HOBBY}} Enthusiast | Suche jemanden für {{ACTIVITY}} | {{EMOJI}}',
        tone: 'casual'
      },
      {
        id: 'variant_funny',
        name: 'Humorvoll',
        content: 'Profi im {{HOBBY}} (nicht wirklich) | {{EMOJI}} > 🍕',
        tone: 'funny'
      },
      {
        id: 'variant_genuine',
        name: 'Authentisch',
        content: 'Einfach auf der Suche nach echten Gesprächen und {{HOBBY}}',
        tone: 'genuine'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{HOBBY}}',
        description: 'Ein Hobby',
        examples: ['Wandern', 'Kochen', 'Musik', 'Filme']
      },
      {
        key: '{{ACTIVITY}}',
        description: 'Eine Aktivität',
        examples: ['Kaffee', 'Spaziergänge', 'Konzerte', 'Spieleabende']
      },
      {
        key: '{{EMOJI}}',
        description: 'Ein Emoji',
        examples: ['☕', '🎵', '🏔️', '🎬']
      }
    ],
    tips: [
      'Vorname reicht, kein Nachname',
      'Ungefähre Altersgruppe statt exaktem Alter',
      'Hobbys statt Beruf in den Vordergrund'
    ],
    doNot: [
      'Arbeitsplatz oder Arbeitgeber nennen',
      'Genaue Adresse oder Stadtteil',
      'Voller Name oder Social Media Handles'
    ]
  },
  {
    id: 'sm_post_travel',
    name: 'Reise-Post',
    category: 'social_media',
    subcategory: 'posts',
    description: 'Urlaubspost ohne Sicherheitsrisiken',
    privacyScore: 75,
    popularity: 650,
    tags: ['instagram', 'facebook'],
    preview: 'Schöne Zeit gehabt! 🌴',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_vague',
        name: 'Vage',
        content: 'Schöne Zeit gehabt! {{EMOJI}}',
        tone: 'casual'
      },
      {
        id: 'variant_past',
        name: 'Vergangenheit',
        content: 'Throwback zu einer wunderschönen Reise {{EMOJI}}',
        tone: 'nostalgic'
      },
      {
        id: 'variant_general',
        name: 'Allgemein',
        content: 'Manchmal muss man einfach raus. {{EMOJI}}',
        tone: 'philosophical'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{EMOJI}}',
        description: 'Passendes Emoji',
        examples: ['🌴', '🏔️', '🌊', '✈️', '🌅']
      }
    ],
    tips: [
      'Poste erst NACH der Reise',
      'Keine Echtzeit-Standorte',
      'Allgemeine Beschreibung statt genauer Ort'
    ],
    doNot: [
      'Während du weg bist posten',
      'Genauen Standort taggen',
      'Reisedaten verraten',
      'Hotel oder Unterkunft nennen'
    ]
  },
  // Job Application Templates
  {
    id: 'job_cv_summary',
    name: 'Lebenslauf-Kurzprofil',
    category: 'job_application',
    subcategory: 'cv_summary',
    description: 'Professionelles Profil ohne zu viele Details',
    privacyScore: 75,
    popularity: 540,
    tags: ['cv', 'resume', 'linkedin'],
    preview: 'Erfahrene Fachkraft im Bereich Marketing mit Schwerpunkt Digital...',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_experienced',
        name: 'Erfahren',
        content: 'Erfahrene Fachkraft im Bereich {{BRANCHE}} mit Schwerpunkt {{SKILL}}. Mehrjährige Berufserfahrung in {{REGION}}.',
        tone: 'professional'
      },
      {
        id: 'variant_results',
        name: 'Ergebnisorientiert',
        content: 'Ergebnisorientierter {{BRANCHE}}-Experte mit nachweislichen Erfolgen in {{SKILL}} und {{SKILL2}}.',
        tone: 'professional'
      },
      {
        id: 'variant_passionate',
        name: 'Leidenschaftlich',
        content: 'Leidenschaftlicher {{BRANCHE}}-Spezialist mit Fokus auf {{SKILL}}. Stets auf der Suche nach neuen Herausforderungen.',
        tone: 'enthusiastic'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{BRANCHE}}',
        description: 'Deine Branche',
        examples: ['Marketing', 'IT', 'Finance', 'HR', 'Sales']
      },
      {
        key: '{{SKILL}}',
        description: 'Hauptfähigkeit',
        examples: ['Digital Marketing', 'Projektmanagement', 'Datenanalyse']
      },
      {
        key: '{{SKILL2}}',
        description: 'Zweite Fähigkeit',
        examples: ['Teamführung', 'Strategieentwicklung', 'Kundenbetreuung']
      },
      {
        key: '{{REGION}}',
        description: 'Region (allgemein)',
        examples: ['DACH-Region', 'Europa', 'Deutschland']
      }
    ],
    tips: [
      'Vermeide genaue Jahreszahlen',
      'Nutze "mehrjährig" statt "5 Jahre"',
      'Region statt Stadt'
    ],
    doNot: [
      'Genaues Alter oder Geburtsjahr',
      'Frühere Arbeitgeber mit Namen',
      'Exakte Gehaltsinformationen'
    ]
  },
  {
    id: 'job_cover_intro',
    name: 'Anschreiben-Einleitung',
    category: 'job_application',
    subcategory: 'cover_letter',
    description: 'Professioneller Einstieg ohne zu persönlich zu werden',
    privacyScore: 80,
    popularity: 420,
    tags: ['bewerbung', 'anschreiben'],
    preview: 'Mit großem Interesse habe ich Ihre Stellenausschreibung gelesen...',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_interest',
        name: 'Interesse',
        content: 'Mit großem Interesse habe ich Ihre Stellenausschreibung für die Position im Bereich {{BRANCHE}} gelesen. Meine Erfahrung in {{SKILL}} und meine Leidenschaft für {{THEMA}} machen mich zu einem idealen Kandidaten.',
        tone: 'professional'
      },
      {
        id: 'variant_referral',
        name: 'Mit Empfehlung',
        content: 'Auf Empfehlung bewerbe ich mich für die ausgeschriebene Position. Mein Hintergrund in {{BRANCHE}} und meine Expertise in {{SKILL}} passen hervorragend zu Ihren Anforderungen.',
        tone: 'professional'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{BRANCHE}}',
        description: 'Bereich der Stelle',
        examples: ['Marketing', 'IT', 'Vertrieb']
      },
      {
        key: '{{SKILL}}',
        description: 'Relevante Fähigkeit',
        examples: ['Projektmanagement', 'Datenanalyse', 'Kundenbetreuung']
      },
      {
        key: '{{THEMA}}',
        description: 'Thema/Bereich',
        examples: ['digitale Transformation', 'Innovation', 'Teamarbeit']
      }
    ],
    tips: [
      'Keine persönlichen Geschichten im ersten Absatz',
      'Fokus auf Qualifikationen, nicht Lebensumstände'
    ],
    doNot: [
      'Familienstand erwähnen',
      'Gesundheitliche Gründe für Wechsel',
      'Finanzielle Motivation'
    ]
  },
  // Online Forms Templates
  {
    id: 'form_registration',
    name: 'Minimale Registrierung',
    category: 'online_forms',
    subcategory: 'registration',
    description: 'Nur notwendige Angaben für Account-Erstellung',
    privacyScore: 90,
    popularity: 380,
    tags: ['signup', 'registration', 'account'],
    preview: 'Username statt Realname...',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_username',
        name: 'Mit Username',
        content: 'Name: {{USERNAME}}\nE-Mail: {{ALIAS_EMAIL}}',
        tone: 'minimal'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{USERNAME}}',
        description: 'Ein Pseudonym/Username',
        examples: ['CoffeeExplorer', 'NightOwl42', 'PixelWanderer']
      },
      {
        key: '{{ALIAS_EMAIL}}',
        description: 'E-Mail mit Alias',
        examples: ['vorname+servicename@email.de']
      }
    ],
    tips: [
      'Nutze E-Mail-Aliase (vorname+dienst@email.de)',
      'Username statt echtem Namen',
      'Optionale Felder leer lassen'
    ],
    doNot: [
      'Echten vollen Namen angeben',
      'Haupt-E-Mail-Adresse nutzen',
      'Optionale Felder ausfüllen'
    ]
  },
  {
    id: 'form_contact',
    name: 'Kontaktformular',
    category: 'online_forms',
    subcategory: 'contact',
    description: 'Anfrage ohne zu viel preiszugeben',
    privacyScore: 85,
    popularity: 290,
    tags: ['contact', 'inquiry'],
    preview: 'Anfrage zu Ihrem Produkt...',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_product',
        name: 'Produktanfrage',
        content: 'Betreff: Anfrage zu {{PRODUKT}}\n\nGuten Tag,\n\nich interessiere mich für {{PRODUKT}} und hätte einige Fragen:\n\n{{FRAGE}}\n\nBitte kontaktieren Sie mich per E-Mail.\n\nMit freundlichen Grüßen',
        tone: 'professional'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{PRODUKT}}',
        description: 'Produkt/Service',
        examples: ['Ihr Softwareprodukt', 'Ihre Dienstleistung']
      },
      {
        key: '{{FRAGE}}',
        description: 'Deine Frage',
        examples: ['Gibt es eine Testversion?', 'Welche Funktionen sind enthalten?']
      }
    ],
    tips: [
      'Nur Vorname oder gar keinen Namen',
      'Keine Telefonnummer wenn nicht nötig',
      'E-Mail-Alias verwenden'
    ],
    doNot: [
      'Vollständige Adresse angeben',
      'Telefonnummer teilen',
      'Arbeitgeber erwähnen'
    ]
  },
  // Email Response Templates
  {
    id: 'email_marketing_optout',
    name: 'Marketing-Abmeldung',
    category: 'email_responses',
    subcategory: 'marketing_optout',
    description: 'Höfliche Abmeldung von Werbe-E-Mails',
    privacyScore: 95,
    popularity: 560,
    tags: ['marketing', 'newsletter', 'abmeldung'],
    preview: 'Bitte entfernen Sie mich aus Ihrem Verteiler...',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_polite',
        name: 'Höflich',
        content: 'Betreff: Abmeldung vom Newsletter\n\nGuten Tag,\n\nbitte entfernen Sie meine E-Mail-Adresse aus Ihrem Verteiler. Ich möchte keine weiteren Marketing-E-Mails erhalten.\n\nMit freundlichen Grüßen',
        tone: 'polite'
      },
      {
        id: 'variant_firm',
        name: 'Bestimmt',
        content: 'Betreff: Sofortige Abmeldung gefordert\n\nGuten Tag,\n\nich fordere Sie auf, meine E-Mail-Adresse unverzüglich aus allen Verteilern zu entfernen. Dies gilt für sämtliche Marketing- und Werbenachrichten.\n\nIch erwarte eine Bestätigung.',
        tone: 'firm'
      }
    ],
    customizable: false,
    placeholders: [],
    tips: [
      'Kurz und sachlich bleiben',
      'Keine Erklärung nötig',
      'Um Bestätigung bitten'
    ],
    doNot: [
      'Persönliche Gründe nennen',
      'Sich entschuldigen',
      'Zusätzliche Informationen geben'
    ]
  },
  {
    id: 'email_data_request_decline',
    name: 'Datenanfrage ablehnen',
    category: 'email_responses',
    subcategory: 'data_requests',
    description: 'Höfliche Ablehnung einer Datenanfrage',
    privacyScore: 92,
    popularity: 340,
    tags: ['data', 'request', 'decline'],
    preview: 'Vielen Dank für Ihre Anfrage, jedoch...',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_polite',
        name: 'Höflich',
        content: 'Betreff: Re: Ihre Anfrage\n\nGuten Tag,\n\nvielen Dank für Ihre Anfrage. Leider kann ich die gewünschten Informationen nicht bereitstellen, da diese persönlicher Natur sind.\n\nIch bitte um Verständnis.\n\nMit freundlichen Grüßen',
        tone: 'polite'
      },
      {
        id: 'variant_firm',
        name: 'Bestimmt',
        content: 'Betreff: Re: Ihre Anfrage\n\nGuten Tag,\n\ndie von Ihnen angeforderten Daten kann und werde ich nicht bereitstellen. Bitte sehen Sie von weiteren Anfragen dieser Art ab.\n\nMit freundlichen Grüßen',
        tone: 'firm'
      }
    ],
    customizable: false,
    placeholders: [],
    tips: [
      'Keine Begründung schuldig',
      'Kurz und bestimmt'
    ],
    doNot: [
      'Sich rechtfertigen',
      'Alternative Daten anbieten'
    ]
  },
  {
    id: 'email_consent_withdrawal',
    name: 'Einwilligung widerrufen',
    category: 'email_responses',
    subcategory: 'consent_withdrawal',
    description: 'Widerruf einer Datenverarbeitungs-Einwilligung',
    privacyScore: 98,
    popularity: 410,
    tags: ['consent', 'withdrawal', 'gdpr'],
    preview: 'Hiermit widerrufe ich meine Einwilligung...',
    privacyAnalysis: {
      piiCount: 0,
      locationRevealed: false,
      ageRevealed: false,
      employerRevealed: false
    },
    variants: [
      {
        id: 'variant_formal',
        name: 'Formell',
        content: 'Betreff: Widerruf meiner Einwilligung zur Datenverarbeitung\n\nGuten Tag,\n\nhiermit widerrufe ich meine zuvor erteilte Einwilligung zur Verarbeitung meiner personenbezogenen Daten mit sofortiger Wirkung.\n\nDies betrifft insbesondere:\n- {{DATENARTEN}}\n\nBitte bestätigen Sie den Widerruf und die Einstellung der Datenverarbeitung.\n\nMit freundlichen Grüßen',
        tone: 'formal'
      }
    ],
    customizable: true,
    placeholders: [
      {
        key: '{{DATENARTEN}}',
        description: 'Welche Daten betroffen sind',
        examples: ['E-Mail-Adresse für Newsletter', 'Nutzungsdaten für Personalisierung']
      }
    ],
    tips: [
      'Präzise angeben welche Einwilligung',
      'Bestätigung anfordern'
    ],
    doNot: [
      'Gründe für den Widerruf nennen',
      'Sich entschuldigen'
    ]
  }
];

// GDPR Request Templates
const GDPR_TEMPLATES = {
  access: {
    subject: 'Auskunftsanfrage nach Art. 15 DSGVO',
    body: `Sehr geehrte Damen und Herren,

hiermit mache ich von meinem Auskunftsrecht gemäß Art. 15 DSGVO Gebrauch.

Ich bitte Sie, mir folgende Informationen innerhalb der gesetzlichen Frist von einem Monat mitzuteilen:

1. Ob Sie personenbezogene Daten über mich verarbeiten
2. Welche Kategorien personenbezogener Daten Sie verarbeiten
3. Die Verarbeitungszwecke
4. Die Empfänger oder Kategorien von Empfängern
5. Die geplante Speicherdauer
6. Informationen über die Herkunft der Daten
7. Das Bestehen einer automatisierten Entscheidungsfindung einschließlich Profiling

Bitte übermitteln Sie mir eine Kopie der personenbezogenen Daten in einem gängigen elektronischen Format.

Mit freundlichen Grüßen
{{NAME}}`,
    placeholders: [
      {
        key: '{{NAME}}',
        description: 'Dein Name (für formelle Anfragen nötig)'
      }
    ],
    legalBasis: 'Art. 15 DSGVO - Auskunftsrecht der betroffenen Person',
    responseDeadline: '30 Tage',
    tips: [
      'Per E-Mail oder Einschreiben senden',
      'Kopie aufbewahren',
      'Frist notieren'
    ]
  },
  deletion: {
    subject: 'Antrag auf Löschung personenbezogener Daten (Art. 17 DSGVO)',
    body: `Sehr geehrte Damen und Herren,

hiermit mache ich von meinem Recht auf Löschung gemäß Art. 17 DSGVO Gebrauch.

Ich fordere Sie auf, sämtliche über mich gespeicherten personenbezogenen Daten unverzüglich zu löschen.

Betroffen sind insbesondere:
{{DATENARTEN}}

Die Löschung ist aus folgendem Grund geboten:
- Die Daten sind für die Zwecke, für die sie erhoben wurden, nicht mehr notwendig
- Ich widerrufe meine Einwilligung und es gibt keine andere Rechtsgrundlage

Bitte bestätigen Sie die vollständige Löschung innerhalb der gesetzlichen Frist von einem Monat.

Sollten Sie die Daten an Dritte weitergegeben haben, bitte ich Sie, diese ebenfalls über meinen Löschungsantrag zu informieren.

Mit freundlichen Grüßen
{{NAME}}`,
    placeholders: [
      {
        key: '{{DATENARTEN}}',
        description: 'Welche Daten gelöscht werden sollen',
        examples: ['E-Mail-Adresse', 'Kundenkonto', 'Bestellhistorie', 'Alle gespeicherten Daten']
      },
      {
        key: '{{NAME}}',
        description: 'Dein Name (für formelle Anfragen nötig)'
      }
    ],
    legalBasis: 'Art. 17 DSGVO - Recht auf Löschung ("Recht auf Vergessenwerden")',
    responseDeadline: '30 Tage',
    tips: [
      'Per Einschreiben senden für Nachweis',
      'Kopie der Anfrage aufbewahren',
      'Frist notieren und nachfassen',
      'Bei Ablehnung: Begründung verlangen'
    ]
  },
  rectification: {
    subject: 'Antrag auf Berichtigung personenbezogener Daten (Art. 16 DSGVO)',
    body: `Sehr geehrte Damen und Herren,

hiermit mache ich von meinem Recht auf Berichtigung gemäß Art. 16 DSGVO Gebrauch.

Ich bitte Sie, folgende unrichtige personenbezogene Daten unverzüglich zu berichtigen:

Falsche Daten: {{FALSCHE_DATEN}}
Korrekte Daten: {{KORREKTE_DATEN}}

Bitte bestätigen Sie die Berichtigung innerhalb der gesetzlichen Frist.

Mit freundlichen Grüßen
{{NAME}}`,
    placeholders: [
      {
        key: '{{FALSCHE_DATEN}}',
        description: 'Die falschen Daten',
        examples: ['Falsche Adresse: Musterstraße 1', 'Falscher Name: Max Muster']
      },
      {
        key: '{{KORREKTE_DATEN}}',
        description: 'Die korrekten Daten',
        examples: ['Korrekte Adresse: Beispielweg 2', 'Korrekter Name: Maximilian Muster']
      },
      {
        key: '{{NAME}}',
        description: 'Dein Name'
      }
    ],
    legalBasis: 'Art. 16 DSGVO - Recht auf Berichtigung',
    responseDeadline: '30 Tage',
    tips: [
      'Konkret angeben was falsch ist',
      'Nachweis beifügen wenn möglich'
    ]
  },
  portability: {
    subject: 'Antrag auf Datenübertragbarkeit (Art. 20 DSGVO)',
    body: `Sehr geehrte Damen und Herren,

hiermit mache ich von meinem Recht auf Datenübertragbarkeit gemäß Art. 20 DSGVO Gebrauch.

Ich bitte Sie, mir die mich betreffenden personenbezogenen Daten, die ich Ihnen bereitgestellt habe, in einem strukturierten, gängigen und maschinenlesbaren Format zu übermitteln.

{{UEBERTRAGUNG}}

Bitte übermitteln Sie die Daten innerhalb der gesetzlichen Frist von einem Monat.

Mit freundlichen Grüßen
{{NAME}}`,
    placeholders: [
      {
        key: '{{UEBERTRAGUNG}}',
        description: 'Wohin die Daten übertragen werden sollen',
        examples: [
          'Bitte übermitteln Sie die Daten an meine E-Mail-Adresse.',
          'Bitte übertragen Sie die Daten direkt an [Neuer Anbieter].'
        ]
      },
      {
        key: '{{NAME}}',
        description: 'Dein Name'
      }
    ],
    legalBasis: 'Art. 20 DSGVO - Recht auf Datenübertragbarkeit',
    responseDeadline: '30 Tage',
    tips: [
      'Gilt nur für Daten, die du selbst bereitgestellt hast',
      'Format: CSV, JSON oder XML üblich'
    ]
  },
  objection: {
    subject: 'Widerspruch gegen Datenverarbeitung (Art. 21 DSGVO)',
    body: `Sehr geehrte Damen und Herren,

hiermit widerspreche ich gemäß Art. 21 DSGVO der Verarbeitung meiner personenbezogenen Daten.

Der Widerspruch bezieht sich auf:
{{VERARBEITUNG}}

Gründe für meinen Widerspruch:
{{GRUENDE}}

Ich fordere Sie auf, die betreffende Verarbeitung unverzüglich einzustellen.

Bitte bestätigen Sie den Erhalt dieses Widerspruchs und die Einstellung der Verarbeitung.

Mit freundlichen Grüßen
{{NAME}}`,
    placeholders: [
      {
        key: '{{VERARBEITUNG}}',
        description: 'Welche Verarbeitung',
        examples: ['Nutzung meiner Daten für Direktwerbung', 'Profiling für personalisierte Werbung']
      },
      {
        key: '{{GRUENDE}}',
        description: 'Begründung (optional)',
        examples: ['Ich möchte keine personalisierte Werbung erhalten.', 'Aufgrund meiner besonderen Situation.']
      },
      {
        key: '{{NAME}}',
        description: 'Dein Name'
      }
    ],
    legalBasis: 'Art. 21 DSGVO - Widerspruchsrecht',
    responseDeadline: '30 Tage',
    tips: [
      'Bei Direktwerbung: Keine Begründung nötig',
      'Ansonsten: Gründe aus besonderer Situation angeben'
    ]
  }
};

// Template favorites storage (anonymized, in-memory)
const templateFavorites = new Map();

// Helper: Calculate privacy score for text
function calculateTemplatePrivacyScore(text, context = 'general') {
  let score = 100;

  const deductions = {
    full_name: -25,
    age_exact: -15,
    age_decade: -5,
    city: -20,
    country: -5,
    employer_specific: -25,
    employer_industry: -10,
    job_title_specific: -15,
    job_title_general: -5,
    family_status: -10,
    phone_number: -30,
    email: -20,
    birthdate: -20,
    address: -30
  };

  // Check for various PII patterns
  if (/[A-ZÄÖÜ][a-zäöüß]+\s+[A-ZÄÖÜ][a-zäöüß]+/.test(text)) score += deductions.full_name;
  if (/\b\d{1,2}\s*(?:Jahre|J\.|years old)\b/i.test(text)) score += deductions.age_exact;
  if (/\b(?:20er|30er|40er|50er|60er)\b/i.test(text)) score += deductions.age_decade;
  if (/\b(?:München|Berlin|Hamburg|Frankfurt|Köln|Stuttgart|Düsseldorf|Wien|Zürich)\b/i.test(text)) score += deductions.city;
  if (/\b(?:arbeite bei|bei der|angestellt bei)\s+[A-ZÄÖÜ][a-zäöüß]+/i.test(text)) score += deductions.employer_specific;
  if (/\b(?:verheiratet|ledig|geschieden|verwitwet)\b/i.test(text)) score += deductions.family_status;
  if (/(?:\+49|0049|0)[\s]?(?:\d[\s]?){9,14}/.test(text)) score += deductions.phone_number;
  if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(text)) score += deductions.email;
  if (/\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b/.test(text)) score += deductions.birthdate;
  if (/\b[\wäöüßÄÖÜ]+(?:straße|str\.|weg|gasse|platz|allee)\s+\d+/i.test(text)) score += deductions.address;

  return Math.max(0, score);
}

// Helper: Analyze text and find issues
function analyzeTextForPrivacy(text, context = 'general') {
  const issues = [];

  // Name detection
  const nameMatch = text.match(/\b([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)\b/);
  if (nameMatch && /^[A-ZÄÖÜ][a-zäöüß]+\s+[A-ZÄÖÜ][a-zäöüß]+$/.test(nameMatch[0])) {
    issues.push({
      type: 'name',
      found: nameMatch[0],
      severity: 'high',
      suggestion: 'Entferne deinen echten Namen oder nutze einen Spitznamen',
      deduction: 25
    });
  }

  // Age detection
  const ageMatch = text.match(/\b(\d{1,2})\s*(?:Jahre|J\.|years old|y\/o)?\b/i);
  if (ageMatch && parseInt(ageMatch[1]) >= 18 && parseInt(ageMatch[1]) <= 99) {
    if (/\d{1,2}\s*(?:Jahre|J\.|years)/i.test(text)) {
      issues.push({
        type: 'age',
        found: ageMatch[0],
        severity: 'medium',
        suggestion: 'Alter weglassen oder nur Dekade angeben (20er)',
        deduction: 15
      });
    }
  }

  // Location detection
  const cities = ['München', 'Berlin', 'Hamburg', 'Frankfurt', 'Köln', 'Stuttgart', 'Düsseldorf', 'Wien', 'Zürich', 'Leipzig', 'Dresden', 'Hannover', 'Nürnberg', 'Bremen', 'Dortmund'];
  for (const city of cities) {
    if (text.includes(city)) {
      issues.push({
        type: 'location',
        found: city,
        severity: 'high',
        suggestion: 'Nur Land oder Region angeben, nicht die Stadt',
        deduction: 20
      });
      break;
    }
  }

  // Employer detection
  const employerMatch = text.match(/(?:arbeite bei|bei der|bei|angestellt bei|tätig bei)\s+([A-ZÄÖÜ][a-zäöüßA-ZÄÖÜ]+)/i);
  if (employerMatch) {
    issues.push({
      type: 'employer',
      found: employerMatch[1],
      severity: 'high',
      suggestion: 'Nur Branche nennen, nicht den Arbeitgeber',
      deduction: 25
    });
  }

  // Phone detection
  const phoneMatch = text.match(/(?:\+49|0049|0)[\s]?(?:\d[\s]?){9,14}/);
  if (phoneMatch) {
    issues.push({
      type: 'phone',
      found: phoneMatch[0],
      severity: 'critical',
      suggestion: 'Telefonnummer entfernen',
      deduction: 30
    });
  }

  // Email detection
  const emailMatch = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  if (emailMatch) {
    issues.push({
      type: 'email',
      found: emailMatch[0],
      severity: 'high',
      suggestion: 'E-Mail-Adresse entfernen oder Alias verwenden',
      deduction: 20
    });
  }

  // Birthdate detection
  const birthdateMatch = text.match(/\b(\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\b/);
  if (birthdateMatch) {
    issues.push({
      type: 'birthdate',
      found: birthdateMatch[0],
      severity: 'high',
      suggestion: 'Geburtsdatum entfernen',
      deduction: 20
    });
  }

  // Address detection
  const addressMatch = text.match(/[\wäöüßÄÖÜ]+(?:straße|str\.|weg|gasse|platz|allee)\s+\d+[a-z]?/i);
  if (addressMatch) {
    issues.push({
      type: 'address',
      found: addressMatch[0],
      severity: 'critical',
      suggestion: 'Adresse entfernen',
      deduction: 30
    });
  }

  return issues;
}

// Helper: Generate improved version of text
function generateImprovedText(text, issues) {
  let improved = text;

  for (const issue of issues) {
    switch (issue.type) {
      case 'name':
        // Replace with just first letter
        const nameParts = issue.found.split(' ');
        if (nameParts.length > 1) {
          improved = improved.replace(issue.found, nameParts[0].charAt(0) + '.');
        }
        break;
      case 'age':
        // Remove age
        improved = improved.replace(new RegExp(issue.found.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ',?\\s*', 'gi'), '');
        break;
      case 'location':
        // Replace with region
        const regionMap = {
          'München': 'Bayern',
          'Berlin': 'Deutschland',
          'Hamburg': 'Norddeutschland',
          'Frankfurt': 'Hessen',
          'Köln': 'NRW',
          'Stuttgart': 'Baden-Württemberg',
          'Wien': 'Österreich',
          'Zürich': 'Schweiz'
        };
        improved = improved.replace(issue.found, regionMap[issue.found] || 'Deutschland');
        break;
      case 'employer':
        // Replace with industry
        improved = improved.replace(new RegExp(`(?:bei|bei der)\\s+${issue.found}`, 'gi'), 'in der Branche');
        break;
      case 'phone':
      case 'email':
      case 'birthdate':
      case 'address':
        // Remove entirely
        improved = improved.replace(issue.found, '').replace(/\s{2,}/g, ' ');
        break;
    }
  }

  // Clean up
  improved = improved.replace(/\s+/g, ' ').replace(/\s+([.,])/g, '$1').trim();

  return improved;
}

// Helper: Get privacy grade from score
function getPrivacyGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
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
    version: '11.0.0',
    features: ['quickCheck', 'batchAnalysis', 'smartRewrite', 'providerFallback', 'multiLanguage', 'offlinePatterns', 'predictivePrivacy', 'digitalFootprint', 'privacyCoach', 'privacyTemplates'],
    languages: SUPPORTED_LANGUAGES,
    endpoints: {
      v1: ['/analyze', '/rewrite', '/howto'],
      v2: [
        '/api/v2/analyze', '/api/v2/rewrite', '/api/v2/analyze/batch', '/api/v2/analyze/predictive',
        '/api/v2/categories', '/api/v2/patterns', '/api/v2/health', '/api/v2/languages',
        '/api/v2/ping', '/api/v2/patterns/offline', '/api/v2/risk-factors',
        '/api/v2/breach-scenarios', '/api/v2/correlation-methods',
        '/api/v2/footprint/scan', '/api/v2/footprint/breach-check', '/api/v2/footprint/social-scan',
        '/api/v2/footprint/databroker-scan', '/api/v2/footprint/optout-request', '/api/v2/footprint/optout-status/:id',
        '/api/v2/footprint/databrokers', '/api/v2/footprint/breach-database', '/api/v2/footprint/monitor',
        '/api/v2/footprint/social-platforms',
        '/api/v2/coach/chat', '/api/v2/coach/explain', '/api/v2/coach/analyze-risk',
        '/api/v2/coach/topics', '/api/v2/coach/topic/:id', '/api/v2/coach/session',
        '/api/v2/coach/feedback', '/api/v2/coach/quick-tips',
        '/api/v2/templates/categories', '/api/v2/templates/category/:id', '/api/v2/templates/:id',
        '/api/v2/templates/customize', '/api/v2/templates/analyze', '/api/v2/templates/gdpr/:type',
        '/api/v2/templates/favorite', '/api/v2/templates/favorites', '/api/v2/templates/search'
      ]
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
    'phone', 'email', 'date_of_birth', 'age', 'german_date',
    // Location
    'gps_coordinates', 'license_plate', 'address', 'postal_code',
    // Context
    'vacation_hint'
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

// ===========================================
// Phase 5: Predictive Privacy Functions
// ===========================================

// Calculate deanonymization risk score (k-Anonymity concept)
// Formula: deanon_risk = 1 - ∏(1 - uniqueness_score[i])
function calculateDeanonymizationRisk(findings) {
  if (!findings || findings.length === 0) {
    return {
      deanonymizationRisk: 0,
      kAnonymityEstimate: 'hoch',
      kValue: '>1000',
      explanation: 'Keine identifizierenden Datenpunkte gefunden',
      contributingFactors: []
    };
  }

  // Get uniqueness scores for each finding
  const contributingFactors = [];
  let combinedProbability = 1;

  for (const finding of findings) {
    const riskFactor = RISK_FACTORS[finding.type];
    if (riskFactor) {
      const uniqueness = riskFactor.uniquenessScore;
      combinedProbability *= (1 - uniqueness);

      contributingFactors.push({
        type: finding.type,
        match: finding.match,
        uniquenessScore: uniqueness,
        description: riskFactor.description
      });
    }
  }

  // Deanonymization risk = 1 - combined probability of NOT being identified
  const deanonymizationRisk = Math.round((1 - combinedProbability) * 100);

  // Estimate k-Anonymity (how many people share this exact data combination)
  let kAnonymityEstimate, kValue;
  if (deanonymizationRisk >= 95) {
    kAnonymityEstimate = 'sehr niedrig';
    kValue = '1-5';
  } else if (deanonymizationRisk >= 80) {
    kAnonymityEstimate = 'niedrig';
    kValue = '5-50';
  } else if (deanonymizationRisk >= 50) {
    kAnonymityEstimate = 'mittel';
    kValue = '50-500';
  } else if (deanonymizationRisk >= 20) {
    kAnonymityEstimate = 'gut';
    kValue = '500-5000';
  } else {
    kAnonymityEstimate = 'hoch';
    kValue = '>5000';
  }

  // Sort by uniqueness score (highest risk first)
  contributingFactors.sort((a, b) => b.uniquenessScore - a.uniquenessScore);

  const explanation = deanonymizationRisk >= 80
    ? 'Die Kombination der Daten macht dich nahezu eindeutig identifizierbar'
    : deanonymizationRisk >= 50
    ? 'Mit diesen Daten kannst du wahrscheinlich identifiziert werden'
    : deanonymizationRisk >= 20
    ? 'Einige Datenpunkte erhöhen das Identifikationsrisiko'
    : 'Geringes Risiko einer Identifikation durch diese Daten';

  return {
    deanonymizationRisk,
    kAnonymityEstimate,
    kValue,
    explanation,
    contributingFactors
  };
}

// Simulate potential data breach scenarios
function simulateBreachScenarios(findings) {
  if (!findings || findings.length === 0) {
    return {
      applicableScenarios: [],
      overallBreachRisk: 0,
      highestRiskScenario: null
    };
  }

  const foundTypes = findings.map(f => f.type);
  const applicableScenarios = [];

  for (const scenario of BREACH_SCENARIOS) {
    // Check how many relevant data types are present
    const matchingTypes = scenario.relevantTypes.filter(t => foundTypes.includes(t));

    if (matchingTypes.length > 0) {
      // Calculate scenario-specific risk based on data overlap
      const overlapRatio = matchingTypes.length / scenario.relevantTypes.length;
      const adjustedProbability = scenario.probability * (0.5 + 0.5 * overlapRatio);

      applicableScenarios.push({
        ...scenario,
        matchingDataTypes: matchingTypes,
        dataOverlapRatio: Math.round(overlapRatio * 100),
        adjustedProbability: Math.round(adjustedProbability * 100),
        riskLevel: adjustedProbability >= 0.4 ? 'hoch' : adjustedProbability >= 0.2 ? 'mittel' : 'niedrig'
      });
    }
  }

  // Sort by adjusted probability (highest risk first)
  applicableScenarios.sort((a, b) => b.adjustedProbability - a.adjustedProbability);

  // Calculate overall breach risk (at least one scenario occurring)
  const overallBreachRisk = applicableScenarios.length > 0
    ? Math.round(applicableScenarios.reduce((max, s) => Math.max(max, s.adjustedProbability), 0))
    : 0;

  return {
    applicableScenarios,
    overallBreachRisk,
    highestRiskScenario: applicableScenarios.length > 0 ? applicableScenarios[0] : null,
    totalScenariosEvaluated: BREACH_SCENARIOS.length
  };
}

// Predict future risk timeline
function predictFutureRisk(findings, deanonRisk) {
  if (!findings || findings.length === 0) {
    return {
      timeline: [],
      longTermRisk: 'niedrig',
      dataDecay: 'Keine sensiblen Daten zur Bewertung'
    };
  }

  const timeline = [];

  // Immediate risks (0-24 hours)
  const immediateTypes = ['password', 'api_key', 'credit_card', 'gps_coordinates'];
  const immediateFindings = findings.filter(f => immediateTypes.includes(f.type));
  if (immediateFindings.length > 0) {
    timeline.push({
      period: '0-24 Stunden',
      riskLevel: 'kritisch',
      risks: [
        'Sofortige Nutzung von Zugangsdaten möglich',
        'Standortverfolgung in Echtzeit',
        'Finanztransaktionen können unmittelbar erfolgen'
      ],
      action: 'Sofort handeln: Passwörter ändern, Karten sperren'
    });
  }

  // Short-term risks (1-7 days)
  const shortTermTypes = ['iban', 'phone', 'email', 'employer'];
  const shortTermFindings = findings.filter(f => shortTermTypes.includes(f.type));
  if (shortTermFindings.length > 0 || immediateFindings.length > 0) {
    timeline.push({
      period: '1-7 Tage',
      riskLevel: 'hoch',
      risks: [
        'Phishing-Angriffe basierend auf gesammelten Daten',
        'SEPA-Lastschriftbetrug möglich',
        'Spam und unerwünschte Kontakte'
      ],
      action: 'Bank informieren, Spam-Filter verschärfen'
    });
  }

  // Medium-term risks (1-4 weeks)
  const mediumTermTypes = ['national_id', 'passport', 'tax_id', 'social_security', 'address'];
  const mediumTermFindings = findings.filter(f => mediumTermTypes.includes(f.type));
  if (mediumTermFindings.length > 0) {
    timeline.push({
      period: '1-4 Wochen',
      riskLevel: 'mittel-hoch',
      risks: [
        'Identitätsmissbrauch wird vorbereitet',
        'Kredit-/Kontoeröffnungen unter falschem Namen',
        'Daten erscheinen in Untergrundforen'
      ],
      action: 'SCHUFA-Warnung aktivieren, Behörden informieren'
    });
  }

  // Long-term risks (1-12 months)
  const persistentTypes = ['date_of_birth', 'health', 'health_insurance', 'child'];
  const persistentFindings = findings.filter(f => persistentTypes.includes(f.type));
  if (deanonRisk > 50 || persistentFindings.length > 0) {
    timeline.push({
      period: '1-12 Monate',
      riskLevel: 'mittel',
      risks: [
        'Langfristige Profilerstellung',
        'Diskriminierung basierend auf Gesundheitsdaten',
        'Daten in Data-Broker-Datenbanken'
      ],
      action: 'Regelmäßige Auskunftsanfragen, Löschungsanträge stellen'
    });
  }

  // Very long-term (1+ years)
  if (deanonRisk > 30) {
    timeline.push({
      period: '1+ Jahre',
      riskLevel: 'niedrig-mittel',
      risks: [
        'Daten werden Teil permanenter Datenbanken',
        'Zukünftige KI-Systeme können alte Daten korrelieren',
        'Reputationsschäden durch alte Informationen'
      ],
      action: 'Digitale Identität regelmäßig überprüfen'
    });
  }

  // Determine long-term risk level
  let longTermRisk = 'niedrig';
  if (timeline.some(t => t.riskLevel === 'kritisch')) {
    longTermRisk = 'sehr hoch';
  } else if (timeline.some(t => t.riskLevel === 'hoch')) {
    longTermRisk = 'hoch';
  } else if (timeline.some(t => t.riskLevel === 'mittel-hoch' || t.riskLevel === 'mittel')) {
    longTermRisk = 'mittel';
  }

  // Data decay info
  const dataDecayInfo = {
    'password': 'Sollte sofort geändert werden - dann wertlos',
    'api_key': 'Sollte sofort rotiert werden - dann wertlos',
    'gps_coordinates': 'Veraltet nach Standortwechsel',
    'vacation_hint': 'Veraltet nach Rückkehr',
    'phone': 'Bleibt oft Jahre gültig',
    'email': 'Bleibt oft Jahre gültig',
    'iban': 'Bleibt lange gültig (Konto behalten)',
    'national_id': 'Gültig bis Dokumentenablauf (Jahre)',
    'date_of_birth': 'Permanent gültig',
    'tax_id': 'Lebenslang gültig'
  };

  const dataDecay = findings.map(f => ({
    type: f.type,
    decay: dataDecayInfo[f.type] || 'Variabel'
  }));

  return {
    timeline,
    longTermRisk,
    dataDecay
  };
}

// Simulate correlation attack possibilities
function simulateCorrelationAttacks(findings) {
  if (!findings || findings.length === 0) {
    return {
      possibleAttacks: [],
      correlationRisk: 0,
      recommendation: 'Keine Korrelationsrisiken identifiziert'
    };
  }

  const foundTypes = findings.map(f => f.type);
  const possibleAttacks = [];

  for (const method of CORRELATION_METHODS) {
    // Check for matching data points
    const matchingPoints = method.dataPoints.filter(dp =>
      foundTypes.some(ft => dp.includes(ft) || ft.includes(dp))
    );

    if (matchingPoints.length > 0) {
      const applicability = matchingPoints.length / method.dataPoints.length;

      possibleAttacks.push({
        id: method.id,
        name: method.name,
        description: method.description,
        difficulty: method.difficulty,
        effectiveness: Math.round(method.effectiveness * applicability * 100),
        matchingDataPoints: matchingPoints,
        example: method.example
      });
    }
  }

  // Sort by effectiveness
  possibleAttacks.sort((a, b) => b.effectiveness - a.effectiveness);

  // Calculate overall correlation risk
  const correlationRisk = possibleAttacks.length > 0
    ? Math.min(100, possibleAttacks.reduce((sum, a) => sum + a.effectiveness, 0) / possibleAttacks.length)
    : 0;

  let recommendation;
  if (correlationRisk >= 70) {
    recommendation = 'Hohes Korrelationsrisiko: Daten können leicht mit anderen Quellen verknüpft werden. Nutze Pseudonyme und verteile Informationen auf getrennte Identitäten.';
  } else if (correlationRisk >= 40) {
    recommendation = 'Mittleres Korrelationsrisiko: Einige Datenpunkte können verknüpft werden. Achte auf konsistente Privacy-Einstellungen.';
  } else if (correlationRisk > 0) {
    recommendation = 'Niedriges Korrelationsrisiko: Begrenzte Verknüpfungsmöglichkeiten, aber Vorsicht bei weiteren Veröffentlichungen.';
  } else {
    recommendation = 'Keine signifikanten Korrelationsrisiken identifiziert.';
  }

  return {
    possibleAttacks,
    correlationRisk: Math.round(correlationRisk),
    recommendation,
    methodsEvaluated: CORRELATION_METHODS.length
  };
}

// API v2: Analyze endpoint
app.post('/api/v2/analyze', async (req, res) => {
  try {
    const { text, context = 'default', lang: requestLang, options = {} } = req.body;
    const includeRewrite = options.includeRewrite === true;
    const quickCheck = options.quickCheck === true;

    // Validate and set language
    const lang = SUPPORTED_LANGUAGES.includes(requestLang) ? requestLang : DEFAULT_LANGUAGE;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({
        error: lang === 'en' ? 'No text provided for analysis' :
               lang === 'fr' ? 'Aucun texte fourni pour l\'analyse' :
               lang === 'es' ? 'No se proporcionó texto para analizar' :
               lang === 'it' ? 'Nessun testo fornito per l\'analisi' :
               'Kein Text zum Analysieren angegeben'
      });
    }

    const startTime = Date.now();

    // Quick Check Mode: Regex-only, no LLM, with caching
    if (quickCheck) {
      const cacheKey = getCacheKey(text, context + '|' + lang);
      const cached = getFromCache(cacheKey);

      if (cached) {
        return res.json({
          ...cached,
          meta: {
            ...cached.meta,
            cached: true
          }
        });
      }

      // Pattern-based detection only
      const patternFindings = detectPatterns(text);

      // Localize findings
      const localizedFindings = patternFindings.map(finding => {
        const localized = getLocalizedCategory(finding.type, lang);
        return {
          ...finding,
          message: localized.message || finding.message,
          suggestion: localized.suggestion || finding.suggestion
        };
      });

      const riskScore = calculateRiskScore(localizedFindings);
      const riskLevel = getRiskLevel(riskScore);

      const result = {
        riskScore,
        riskLevel,
        summary: getLocalizedSummary(localizedFindings.length, lang),
        categories: localizedFindings,
        contextWarning: getLocalizedContextWarning(context, lang),
        meta: {
          mode: 'quickCheck',
          lang,
          processingTime: Date.now() - startTime,
          patternsChecked: Object.keys(PATTERNS).length,
          cached: false
        }
      };

      // Cache the result
      setCache(cacheKey, result);

      return res.json(result);
    }

    // Full Analysis Mode: Regex + LLM
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

    // Step 3: Combine all findings and localize
    const combinedFindings = [...patternFindings, ...gptFindings];

    // Localize pattern findings
    const allCategories = combinedFindings.map(finding => {
      const localized = getLocalizedCategory(finding.type, lang);
      return {
        ...finding,
        message: localized.message || finding.message,
        suggestion: localized.suggestion || finding.suggestion
      };
    });

    // Step 4: Calculate risk score and level
    const riskScore = calculateRiskScore(allCategories);
    const riskLevel = getRiskLevel(riskScore);

    // Step 5: Generate localized summary
    const summary = getLocalizedSummary(allCategories.length, lang);

    // Step 6: Get localized context warning
    const contextWarning = getLocalizedContextWarning(context, lang);

    // Step 7: Build response
    const response = {
      riskScore,
      riskLevel,
      summary,
      categories: allCategories,
      contextWarning,
      meta: {
        mode: 'fullAnalysis',
        lang,
        processingTime: Date.now() - startTime,
        patternsChecked: Object.keys(PATTERNS).length,
        semanticAnalysis: gptFindings.length > 0
      }
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
  const totalRequests = cacheStats.hits + cacheStats.misses;
  const cacheHitRate = totalRequests > 0
    ? ((cacheStats.hits / totalRequests) * 100).toFixed(1) + '%'
    : '0%';

  res.json({
    status: 'ok',
    service: 'achtung.live API',
    version: '11.0.0',
    timestamp: new Date().toISOString(),
    providers: {
      openai: {
        available: providerStatus.openai.available,
        model: 'gpt-4o-mini',
        lastCheck: new Date(providerStatus.openai.lastCheck).toISOString(),
        lastError: providerStatus.openai.lastError
      },
      anthropic: {
        configured: !!anthropic,
        available: providerStatus.anthropic.available,
        model: 'claude-3-haiku-20240307',
        lastCheck: new Date(providerStatus.anthropic.lastCheck).toISOString(),
        lastError: providerStatus.anthropic.lastError
      }
    },
    quickCheck: {
      enabled: true,
      patternsLoaded: Object.keys(PATTERNS).length,
      cacheSize: cacheStats.size,
      cacheHitRate,
      cacheTTL: '5 minutes'
    },
    multiLanguage: {
      enabled: true,
      languages: SUPPORTED_LANGUAGES,
      default: DEFAULT_LANGUAGE
    },
    predictivePrivacy: {
      enabled: true,
      riskFactors: Object.keys(RISK_FACTORS).length,
      breachScenarios: BREACH_SCENARIOS.length,
      correlationMethods: CORRELATION_METHODS.length,
      features: ['deanonymization', 'breachSimulation', 'futureRiskTimeline', 'correlationAttacks']
    },
    digitalFootprint: {
      enabled: true,
      breachDatabase: BREACH_DATABASE.length,
      dataBrokers: DATA_BROKERS.length,
      socialPlatforms: SOCIAL_PLATFORMS.length,
      features: ['breachCheck', 'socialScan', 'dataBrokerScan', 'optOutRequests', 'monitoring']
    },
    privacyCoach: {
      enabled: true,
      privacyTerms: Object.keys(PRIVACY_TERMS).length,
      topicCategories: COACH_TOPICS.categories.length,
      topics: COACH_TOPICS.categories.reduce((sum, c) => sum + c.topics.length, 0),
      topicsWithContent: Object.keys(TOPIC_CONTENT).length,
      riskExplanations: Object.keys(RISK_TYPE_EXPLANATIONS).length,
      quickTips: QUICK_TIPS.length,
      dailyChallenges: DAILY_CHALLENGES.length,
      activeSessions: coachSessions.size,
      features: ['chat', 'explain', 'analyzeRisk', 'topics', 'sessions', 'feedback', 'quickTips']
    },
    privacyTemplates: {
      enabled: true,
      categories: TEMPLATE_CATEGORIES.length,
      templates: PRIVACY_TEMPLATES.length,
      gdprRequestTypes: Object.keys(GDPR_TEMPLATES).length,
      features: ['categories', 'templates', 'customize', 'analyze', 'gdprRequests', 'favorites', 'search']
    },
    pwa: {
      offlinePatternsEndpoint: '/api/v2/patterns/offline',
      pingEndpoint: '/api/v2/ping'
    },
    rateLimits: {
      quickCheck: '60/min (recommended)',
      fullAnalysis: '10/min (recommended)',
      predictiveAnalysis: '5/min (recommended)',
      footprintScan: '5/hour (recommended)',
      breachCheck: '20/min (recommended)',
      coachChat: '30/min (recommended)',
      coachExplain: '20/min (recommended)',
      coachAnalyzeRisk: '10/min (recommended)',
      templatesCustomize: '30/min (recommended)',
      templatesAnalyze: '20/min (recommended)'
    },
    endpoints: {
      v1: ['/analyze', '/rewrite', '/howto'],
      v2: [
        '/api/v2/analyze', '/api/v2/rewrite', '/api/v2/analyze/batch', '/api/v2/analyze/predictive',
        '/api/v2/categories', '/api/v2/patterns', '/api/v2/health', '/api/v2/languages',
        '/api/v2/ping', '/api/v2/patterns/offline', '/api/v2/risk-factors',
        '/api/v2/breach-scenarios', '/api/v2/correlation-methods'
      ],
      footprint: [
        '/api/v2/footprint/scan', '/api/v2/footprint/breach-check', '/api/v2/footprint/social-scan',
        '/api/v2/footprint/databroker-scan', '/api/v2/footprint/optout-request', '/api/v2/footprint/optout-status/:id',
        '/api/v2/footprint/databrokers', '/api/v2/footprint/breach-database', '/api/v2/footprint/monitor',
        '/api/v2/footprint/social-platforms'
      ],
      coach: [
        '/api/v2/coach/chat', '/api/v2/coach/explain', '/api/v2/coach/analyze-risk',
        '/api/v2/coach/topics', '/api/v2/coach/topic/:id', '/api/v2/coach/session',
        '/api/v2/coach/feedback', '/api/v2/coach/quick-tips'
      ],
      templates: [
        '/api/v2/templates/categories', '/api/v2/templates/category/:id', '/api/v2/templates/:id',
        '/api/v2/templates/customize', '/api/v2/templates/analyze', '/api/v2/templates/gdpr/:type',
        '/api/v2/templates/favorite', '/api/v2/templates/favorites', '/api/v2/templates/search'
      ]
    }
  });
});

// GET /api/v2/patterns - List all active detection patterns
app.get('/api/v2/patterns', (req, res) => {
  const patterns = Object.entries(PATTERNS).map(([type, config]) => ({
    type,
    severity: config.severity,
    category: config.category,
    message: config.message,
    suggestion: config.suggestion
    // Note: regex is intentionally not exposed for security
  }));

  // Group by severity
  const bySeverity = {
    critical: patterns.filter(p => p.severity === 'critical').length,
    high: patterns.filter(p => p.severity === 'high').length,
    medium: patterns.filter(p => p.severity === 'medium').length,
    low: patterns.filter(p => p.severity === 'low').length
  };

  // Group by category
  const byCategory = {};
  patterns.forEach(p => {
    byCategory[p.category] = (byCategory[p.category] || 0) + 1;
  });

  res.json({
    version: '10.0',
    patternCount: patterns.length,
    bySeverity,
    byCategory,
    patterns
  });
});

// ===========================================
// API v2 - Phase 4 Endpoints (Multi-Language, PWA)
// ===========================================

// GET /api/v2/languages - List available languages
app.get('/api/v2/languages', (req, res) => {
  res.json({
    available: SUPPORTED_LANGUAGES,
    default: DEFAULT_LANGUAGE,
    labels: {
      de: 'Deutsch',
      en: 'English',
      fr: 'Français',
      es: 'Español',
      it: 'Italiano'
    }
  });
});

// GET /api/v2/ping - Minimal health check for PWA offline detection
app.get('/api/v2/ping', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: Date.now()
  });
});

// GET /api/v2/patterns/offline - Patterns and messages for PWA offline use
app.get('/api/v2/patterns/offline', (req, res) => {
  const lang = SUPPORTED_LANGUAGES.includes(req.query.lang) ? req.query.lang : DEFAULT_LANGUAGE;

  // Build patterns with localized messages
  const patterns = {};
  for (const [type, config] of Object.entries(PATTERNS)) {
    const localized = getLocalizedCategory(type, lang);
    patterns[type] = {
      regex: config.regex.source,
      flags: config.regex.flags,
      severity: config.severity,
      category: config.category,
      message: localized.message || config.message,
      suggestion: localized.suggestion || config.suggestion
    };
  }

  res.json({
    version: '11.0.0',
    lang,
    lastUpdated: new Date().toISOString(),
    patterns,
    messages: LOCALES[lang] || LOCALES[DEFAULT_LANGUAGE],
    contextWarnings: (LOCALES[lang] || LOCALES[DEFAULT_LANGUAGE]).contextWarnings
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

// ===========================================
// API v2 - Phase 5 Endpoints (Predictive Privacy)
// ===========================================

// POST /api/v2/analyze/predictive - Predictive Privacy Analysis
app.post('/api/v2/analyze/predictive', async (req, res) => {
  try {
    const { text, context = 'default', lang: requestLang, options = {} } = req.body;

    // Validate and set language
    const lang = SUPPORTED_LANGUAGES.includes(requestLang) ? requestLang : DEFAULT_LANGUAGE;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({
        error: lang === 'en' ? 'No text provided for analysis' :
               lang === 'de' ? 'Kein Text zum Analysieren angegeben' :
               'Kein Text zum Analysieren angegeben'
      });
    }

    const startTime = Date.now();

    // Step 1: Detect patterns (same as standard analysis)
    const patternFindings = detectPatterns(text);

    // Step 2: GPT-based semantic analysis (unless quickCheck)
    let gptFindings = [];
    if (!options.quickCheck) {
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
        console.error('Predictive GPT-Analyse Fehler:', gptError.message);
      }
    }

    // Step 3: Combine all findings
    const allFindings = [...patternFindings, ...gptFindings];

    // Step 4: Calculate standard risk metrics
    const riskScore = calculateRiskScore(allFindings);
    const riskLevel = getRiskLevel(riskScore);

    // Step 5: Calculate deanonymization risk
    const deanonymization = calculateDeanonymizationRisk(allFindings);

    // Step 6: Simulate breach scenarios
    const breachSimulation = simulateBreachScenarios(allFindings);

    // Step 7: Predict future risk timeline
    const futureRisk = predictFutureRisk(allFindings, deanonymization.deanonymizationRisk);

    // Step 8: Simulate correlation attacks
    const correlationAttacks = simulateCorrelationAttacks(allFindings);

    // Step 9: Generate overall predictive assessment
    const overallAssessment = generatePredictiveAssessment(
      riskScore,
      deanonymization.deanonymizationRisk,
      breachSimulation.overallBreachRisk,
      correlationAttacks.correlationRisk
    );

    // Build response
    res.json({
      // Standard analysis results
      standardAnalysis: {
        riskScore,
        riskLevel,
        summary: getLocalizedSummary(allFindings.length, lang),
        findingsCount: allFindings.length,
        categories: allFindings.map(finding => {
          const localized = getLocalizedCategory(finding.type, lang);
          return {
            ...finding,
            message: localized.message || finding.message,
            suggestion: localized.suggestion || finding.suggestion
          };
        })
      },

      // Predictive analysis results
      predictiveAnalysis: {
        // Deanonymization risk (k-Anonymity)
        deanonymization: {
          risk: deanonymization.deanonymizationRisk,
          kAnonymity: {
            estimate: deanonymization.kAnonymityEstimate,
            kValue: deanonymization.kValue
          },
          explanation: deanonymization.explanation,
          contributingFactors: deanonymization.contributingFactors.slice(0, 5)
        },

        // Breach scenario simulation
        breachSimulation: {
          overallRisk: breachSimulation.overallBreachRisk,
          highestRisk: breachSimulation.highestRiskScenario ? {
            name: breachSimulation.highestRiskScenario.name,
            probability: breachSimulation.highestRiskScenario.adjustedProbability,
            consequences: breachSimulation.highestRiskScenario.consequences
          } : null,
          applicableScenarios: breachSimulation.applicableScenarios.slice(0, 3).map(s => ({
            id: s.id,
            name: s.name,
            probability: s.adjustedProbability,
            riskLevel: s.riskLevel,
            matchingData: s.matchingDataTypes,
            mitigations: s.mitigations
          }))
        },

        // Future risk timeline
        futureRisk: {
          longTermRisk: futureRisk.longTermRisk,
          timeline: futureRisk.timeline,
          dataDecay: futureRisk.dataDecay.slice(0, 5)
        },

        // Correlation attack analysis
        correlationRisk: {
          risk: correlationAttacks.correlationRisk,
          recommendation: correlationAttacks.recommendation,
          possibleAttacks: correlationAttacks.possibleAttacks.slice(0, 3).map(a => ({
            name: a.name,
            effectiveness: a.effectiveness,
            difficulty: a.difficulty,
            example: a.example
          }))
        },

        // Overall assessment
        overallAssessment
      },

      meta: {
        mode: options.quickCheck ? 'quickCheck' : 'fullAnalysis',
        lang,
        processingTime: Date.now() - startTime,
        version: '7.0.0'
      }
    });

  } catch (error) {
    console.error('Predictive Analysis Fehler:', error);
    res.status(500).json({
      error: 'Predictive Analyse fehlgeschlagen',
      details: error.message
    });
  }
});

// Helper: Generate overall predictive assessment
function generatePredictiveAssessment(riskScore, deanonRisk, breachRisk, correlationRisk) {
  const avgRisk = Math.round((100 - riskScore + deanonRisk + breachRisk + correlationRisk) / 4);

  let level, summary, recommendations;

  if (avgRisk >= 75) {
    level = 'kritisch';
    summary = 'Sehr hohe Gefährdung der Privatsphäre. Sofortiges Handeln erforderlich.';
    recommendations = [
      'Sensible Daten sofort aus dem Text entfernen',
      'Betroffene Passwörter/Keys umgehend ändern',
      'Finanzinstitute bei Bankdaten-Leak informieren',
      'Text vor dem Teilen komplett überarbeiten'
    ];
  } else if (avgRisk >= 50) {
    level = 'hoch';
    summary = 'Erhöhtes Privatsphäre-Risiko. Änderungen dringend empfohlen.';
    recommendations = [
      'Identifizierende Informationen entfernen',
      'Kontext-Informationen reduzieren',
      'Pseudonyme statt echter Namen verwenden',
      'Standortdaten vermeiden'
    ];
  } else if (avgRisk >= 25) {
    level = 'mittel';
    summary = 'Moderate Privatsphäre-Risiken vorhanden. Überprüfung empfohlen.';
    recommendations = [
      'Prüfen ob alle Informationen nötig sind',
      'Empfängerkreis einschränken',
      'Sensible Details verallgemeinern'
    ];
  } else {
    level = 'niedrig';
    summary = 'Geringes Privatsphäre-Risiko. Grundlegende Vorsicht beachten.';
    recommendations = [
      'Standardmäßig sparsam mit Daten umgehen',
      'Regelmäßig Privacy-Einstellungen prüfen'
    ];
  }

  return {
    level,
    averageRisk: avgRisk,
    summary,
    recommendations,
    breakdown: {
      privacyScore: riskScore,
      deanonymizationRisk: deanonRisk,
      breachRisk,
      correlationRisk
    }
  };
}

// GET /api/v2/risk-factors - List all risk factors with uniqueness scores
app.get('/api/v2/risk-factors', (req, res) => {
  const factors = Object.entries(RISK_FACTORS).map(([type, data]) => ({
    type,
    ...data
  }));

  // Group by category
  const byCategory = {};
  factors.forEach(f => {
    if (!byCategory[f.category]) {
      byCategory[f.category] = [];
    }
    byCategory[f.category].push(f);
  });

  // Sort each category by uniqueness score
  for (const category of Object.keys(byCategory)) {
    byCategory[category].sort((a, b) => b.uniquenessScore - a.uniquenessScore);
  }

  res.json({
    totalFactors: factors.length,
    categories: Object.keys(byCategory),
    byCategory,
    allFactors: factors.sort((a, b) => b.uniquenessScore - a.uniquenessScore)
  });
});

// GET /api/v2/breach-scenarios - List all breach scenarios
app.get('/api/v2/breach-scenarios', (req, res) => {
  res.json({
    totalScenarios: BREACH_SCENARIOS.length,
    scenarios: BREACH_SCENARIOS.map(s => ({
      id: s.id,
      name: s.name,
      description: s.description,
      baseProbability: Math.round(s.probability * 100),
      relevantDataTypes: s.relevantTypes,
      consequences: s.consequences,
      timeToImpact: s.timeToImpact,
      mitigations: s.mitigations
    }))
  });
});

// GET /api/v2/correlation-methods - List all correlation attack methods
app.get('/api/v2/correlation-methods', (req, res) => {
  res.json({
    totalMethods: CORRELATION_METHODS.length,
    methods: CORRELATION_METHODS.map(m => ({
      id: m.id,
      name: m.name,
      description: m.description,
      dataPoints: m.dataPoints,
      difficulty: m.difficulty,
      baseEffectiveness: Math.round(m.effectiveness * 100),
      example: m.example
    }))
  });
});

// ===========================================
// API v2 - Phase 7 Endpoints (Digital Footprint Scanner)
// ===========================================

// Helper: Generate unique scan ID
function generateScanId() {
  return 'scan_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
}

// Helper: Mask email for privacy
function maskEmail(email) {
  if (!email || !email.includes('@')) return email;
  const [local, domain] = email.split('@');
  const maskedLocal = local.charAt(0) + '***';
  return maskedLocal + '@' + domain;
}

// Helper: Check email against breach database
function checkEmailBreaches(email) {
  const normalizedEmail = email.toLowerCase().trim();
  const emailDomain = normalizedEmail.split('@')[1];

  // Simulate breach check - in production would check against HIBP API or internal DB
  // For demo, we check against known major breaches
  const affectedBreaches = BREACH_DATABASE.filter(breach => {
    // Check if breach affected this domain or is a global breach
    if (breach.dataClasses.includes('email')) {
      // Simulate ~30% chance of being in any major breach
      const hash = normalizedEmail.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
      return (hash + breach.compromisedAccounts) % 3 === 0;
    }
    return false;
  });

  return affectedBreaches;
}

// Helper: Check for social media profiles
function checkSocialProfiles(username, email) {
  const results = [];
  const normalizedUsername = username ? username.toLowerCase().replace(/[^a-z0-9_]/g, '') : null;

  for (const platform of SOCIAL_PLATFORMS) {
    if (platform.checkMethod === 'none') continue;

    // Simulate profile check - in production would actually check URLs
    const found = normalizedUsername ? Math.random() > 0.4 : Math.random() > 0.7;

    if (found && normalizedUsername) {
      const privacyScore = Math.floor(Math.random() * 60) + 20;
      const privacyIssues = [];

      if (privacyScore < 50) {
        privacyIssues.push('Profil ist öffentlich sichtbar');
        if (platform.publicDataFields.includes('location')) {
          privacyIssues.push('Standort öffentlich sichtbar');
        }
        if (platform.publicDataFields.includes('email')) {
          privacyIssues.push('E-Mail-Adresse exponiert');
        }
      }

      const recommendations = [];
      if (privacyScore < 40) {
        recommendations.push('Profil auf privat stellen');
        recommendations.push('Öffentliche Informationen reduzieren');
      }
      if (platform.privacySettings.includes('profile_visibility')) {
        recommendations.push('Profilsichtbarkeit einschränken');
      }

      results.push({
        platform: platform.id,
        displayName: platform.displayName,
        found: true,
        url: platform.profileUrl ? platform.profileUrl.replace('{username}', normalizedUsername) : null,
        username: normalizedUsername,
        displayUsername: platform.usernameFormat.replace('{username}', normalizedUsername),
        isPublic: privacyScore < 50,
        publicData: platform.publicDataFields.slice(0, 4),
        privacyScore,
        privacyIssues,
        recommendations
      });
    } else {
      results.push({
        platform: platform.id,
        displayName: platform.displayName,
        found: false
      });
    }
  }

  return results;
}

// Helper: Check data brokers
function checkDataBrokers(userData, region = 'all') {
  const results = [];
  const filteredBrokers = region === 'all'
    ? DATA_BROKERS
    : DATA_BROKERS.filter(b => b.region === region || b.region === 'Global');

  for (const broker of filteredBrokers) {
    // Simulate check - hash user data to determine if "found"
    const dataString = JSON.stringify(userData);
    const hash = dataString.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
    const found = (hash + broker.id.length) % 4 !== 0; // ~75% chance of being found

    if (found) {
      // Determine which data types might be found
      const possibleData = broker.dataCollected.filter(() => Math.random() > 0.3);

      results.push({
        broker: broker.name,
        id: broker.id,
        website: broker.website,
        category: broker.category,
        region: broker.region,
        dataFound: possibleData,
        confirmed: Math.random() > 0.3 ? true : 'likely',
        optOut: {
          available: broker.optOut.available,
          url: broker.optOut.url,
          method: broker.optOut.method,
          difficulty: broker.optOut.difficulty,
          estimatedDays: broker.optOut.estimatedDays,
          gdprApplicable: broker.optOut.gdprCompliant,
          instructions: broker.optOut.instructions
        },
        riskLevel: broker.riskLevel
      });
    }
  }

  return results;
}

// Helper: Calculate overall footprint risk
function calculateFootprintRisk(breaches, socialProfiles, dataBrokers) {
  let riskScore = 0;

  // Breaches contribute significantly
  riskScore += Math.min(40, breaches.length * 8);

  // Critical breaches add more
  const criticalBreaches = breaches.filter(b => b.severity === 'critical');
  riskScore += criticalBreaches.length * 5;

  // Social profiles with low privacy scores
  const publicProfiles = socialProfiles.filter(p => p.found && p.privacyScore < 40);
  riskScore += Math.min(30, publicProfiles.length * 5);

  // Data brokers
  riskScore += Math.min(30, dataBrokers.length * 2);

  return Math.min(100, riskScore);
}

// In-memory opt-out request storage (would use database in production)
const optOutRequests = new Map();

// POST /api/v2/footprint/scan - Full footprint scan
app.post('/api/v2/footprint/scan', async (req, res) => {
  try {
    const { email, name, phone, username, options = {} } = req.body;

    if (!email && !username && !name) {
      return res.status(400).json({
        error: 'Mindestens eine Suchinformation erforderlich (email, username oder name)'
      });
    }

    const startTime = Date.now();
    const scanId = generateScanId();

    // Check breaches
    const breaches = email ? checkEmailBreaches(email) : [];

    // Check social media
    const socialProfiles = checkSocialProfiles(username, email);
    const foundProfiles = socialProfiles.filter(p => p.found);

    // Check data brokers
    const userData = { email, name, phone, username };
    const dataBrokers = checkDataBrokers(userData, options.region || 'all');

    // Calculate overall risk
    const riskScore = calculateFootprintRisk(breaches, foundProfiles, dataBrokers);
    const criticalFindings = breaches.filter(b => b.severity === 'critical').length +
                            foundProfiles.filter(p => p.privacyScore < 30).length;

    // Generate recommendations
    const recommendations = {
      immediate: [],
      shortTerm: [],
      longTerm: []
    };

    // Immediate actions
    if (breaches.length > 0) {
      recommendations.immediate.push({
        priority: 1,
        action: 'Passwörter für betroffene Dienste ändern',
        reason: `${breaches.length} Datenleck(s) gefunden`,
        affected: breaches.map(b => b.name)
      });
      recommendations.immediate.push({
        priority: 2,
        action: '2-Faktor-Authentifizierung aktivieren',
        reason: 'Schutz vor kompromittierten Zugangsdaten'
      });
    }

    // Short-term actions
    if (dataBrokers.length > 0) {
      const easyOptOuts = dataBrokers.filter(b => b.optOut.difficulty === 'easy');
      recommendations.shortTerm.push({
        priority: 3,
        action: `Opt-out bei ${dataBrokers.length} Data Brokern beantragen`,
        reason: 'Persönliche Daten öffentlich verfügbar',
        easyOptOuts: easyOptOuts.length,
        automatedAvailable: easyOptOuts.filter(b => b.optOut.method === 'web_form').length
      });
    }

    if (foundProfiles.filter(p => p.privacyScore < 50).length > 0) {
      recommendations.shortTerm.push({
        priority: 4,
        action: 'Privacy-Einstellungen in Social Media überprüfen',
        reason: 'Öffentlich sichtbare Profile gefunden'
      });
    }

    // Long-term actions
    recommendations.longTerm.push({
      priority: 5,
      action: 'Regelmäßige Footprint-Scans durchführen',
      reason: 'Neue Datenlecks und Expositionen erkennen'
    });

    recommendations.longTerm.push({
      priority: 6,
      action: 'Google Alerts für den eigenen Namen einrichten',
      reason: 'Zukünftige Erwähnungen überwachen'
    });

    res.json({
      success: true,
      scanId,
      timestamp: new Date().toISOString(),
      summary: {
        overallRisk: riskScore >= 70 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 30 ? 'medium' : 'low',
        riskScore,
        totalExposures: breaches.length + foundProfiles.length + dataBrokers.length,
        criticalFindings,
        actionRequired: recommendations.immediate.length + recommendations.shortTerm.length
      },
      breaches: {
        found: breaches.length > 0,
        count: breaches.length,
        items: breaches.map(b => ({
          id: b.id,
          source: b.name,
          date: b.date,
          severity: b.severity,
          exposedData: b.dataClasses,
          description: b.description,
          isVerified: b.isVerified,
          recommendations: [
            `Passwort für ${b.name} ändern`,
            '2FA aktivieren',
            'Auf Phishing achten'
          ]
        }))
      },
      socialMedia: {
        found: foundProfiles.length > 0,
        count: foundProfiles.length,
        profiles: foundProfiles.slice(0, 10)
      },
      dataBrokers: {
        found: dataBrokers.length > 0,
        count: dataBrokers.length,
        items: dataBrokers.slice(0, 15).map(b => ({
          broker: b.broker,
          category: b.category,
          region: b.region,
          dataFound: b.dataFound,
          optOutUrl: b.optOut.url,
          optOutDifficulty: b.optOut.difficulty,
          estimatedTime: `${b.optOut.estimatedDays} Tage`
        }))
      },
      recommendations,
      meta: {
        processingTime: Date.now() - startTime,
        version: '7.0.0'
      }
    });

  } catch (error) {
    console.error('Footprint Scan Fehler:', error);
    res.status(500).json({
      error: 'Footprint Scan fehlgeschlagen',
      details: error.message
    });
  }
});

// POST /api/v2/footprint/breach-check - Quick breach check
app.post('/api/v2/footprint/breach-check', (req, res) => {
  try {
    const { email, includeDetails = false } = req.body;

    if (!email) {
      return res.status(400).json({
        error: 'Email-Adresse erforderlich'
      });
    }

    const breaches = checkEmailBreaches(email);

    const response = {
      success: true,
      email: maskEmail(email),
      breached: breaches.length > 0,
      breachCount: breaches.length
    };

    if (breaches.length > 0) {
      response.firstBreach = breaches.reduce((min, b) =>
        new Date(b.date) < new Date(min) ? b.date : min, breaches[0].date);
      response.latestBreach = breaches.reduce((max, b) =>
        new Date(b.date) > new Date(max) ? b.date : max, breaches[0].date);
    }

    if (includeDetails) {
      response.breaches = breaches.map(b => ({
        name: b.name,
        domain: b.domain,
        date: b.date,
        compromisedAccounts: b.compromisedAccounts,
        dataClasses: b.dataClasses,
        description: b.description,
        severity: b.severity,
        isVerified: b.isVerified,
        isSensitive: b.isSensitive
      }));
    }

    response.recommendations = breaches.length > 0 ? [
      'Ändern Sie Ihre Passwörter für betroffene Dienste',
      'Verwenden Sie einen Passwort-Manager',
      'Aktivieren Sie 2-Faktor-Authentifizierung',
      'Überprüfen Sie Ihre Konten auf verdächtige Aktivitäten'
    ] : ['Keine unmittelbaren Maßnahmen erforderlich'];

    res.json(response);

  } catch (error) {
    console.error('Breach Check Fehler:', error);
    res.status(500).json({
      error: 'Breach Check fehlgeschlagen',
      details: error.message
    });
  }
});

// POST /api/v2/footprint/social-scan - Social media profile scan
app.post('/api/v2/footprint/social-scan', (req, res) => {
  try {
    const { username, email, platforms = ['all'] } = req.body;

    if (!username && !email) {
      return res.status(400).json({
        error: 'Username oder Email erforderlich'
      });
    }

    const results = checkSocialProfiles(username, email);
    const found = results.filter(r => r.found);
    const notFound = results.filter(r => !r.found).map(r => r.platform);

    res.json({
      success: true,
      profilesFound: found.length,
      profiles: found,
      platformsChecked: SOCIAL_PLATFORMS.map(p => p.id),
      notFound
    });

  } catch (error) {
    console.error('Social Scan Fehler:', error);
    res.status(500).json({
      error: 'Social Media Scan fehlgeschlagen',
      details: error.message
    });
  }
});

// POST /api/v2/footprint/databroker-scan - Data broker scan
app.post('/api/v2/footprint/databroker-scan', (req, res) => {
  try {
    const { name, email, phone, address, region = 'all' } = req.body;

    if (!name && !email && !phone) {
      return res.status(400).json({
        error: 'Mindestens Name, Email oder Telefon erforderlich'
      });
    }

    const userData = { name, email, phone, address };
    const results = checkDataBrokers(userData, region);

    // Calculate summary
    const summary = {
      easyOptOuts: results.filter(r => r.optOut.difficulty === 'easy').length,
      mediumOptOuts: results.filter(r => r.optOut.difficulty === 'medium').length,
      hardOptOuts: results.filter(r => r.optOut.difficulty === 'hard').length,
      gdprBrokers: results.filter(r => r.optOut.gdprApplicable).length,
      automatedOptOutAvailable: results.filter(r => r.optOut.method === 'web_form').length
    };

    // Estimate total time
    const totalDays = results.reduce((sum, r) => sum + r.optOut.estimatedDays, 0);
    summary.totalEstimatedTime = totalDays < 14 ? '1-2 Wochen' :
                                  totalDays < 30 ? '2-4 Wochen' :
                                  totalDays < 60 ? '1-2 Monate' : '2+ Monate';

    // Group by category
    const categories = {};
    results.forEach(r => {
      categories[r.category] = (categories[r.category] || 0) + 1;
    });

    res.json({
      success: true,
      brokersScanned: DATA_BROKERS.length,
      brokersWithData: results.length,
      items: results,
      summary,
      categories
    });

  } catch (error) {
    console.error('Data Broker Scan Fehler:', error);
    res.status(500).json({
      error: 'Data Broker Scan fehlgeschlagen',
      details: error.message
    });
  }
});

// POST /api/v2/footprint/optout-request - Initiate opt-out request
app.post('/api/v2/footprint/optout-request', (req, res) => {
  try {
    const { broker, userData, method = 'automated' } = req.body;

    if (!broker || !userData || !userData.email) {
      return res.status(400).json({
        error: 'Broker und User-Daten (inkl. Email) erforderlich'
      });
    }

    const brokerInfo = DATA_BROKERS.find(b => b.id === broker.toLowerCase());
    if (!brokerInfo) {
      return res.status(404).json({
        error: 'Broker nicht gefunden'
      });
    }

    if (!brokerInfo.optOut.available) {
      return res.status(400).json({
        error: 'Opt-out für diesen Broker nicht verfügbar',
        alternative: brokerInfo.optOut.instructions
      });
    }

    // Create opt-out request
    const requestId = 'optout_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
    const estimatedCompletion = new Date();
    estimatedCompletion.setDate(estimatedCompletion.getDate() + brokerInfo.optOut.estimatedDays);

    const request = {
      requestId,
      broker: brokerInfo.name,
      brokerId: brokerInfo.id,
      status: 'submitted',
      method: method === 'automated' ? 'automated_' + brokerInfo.optOut.method : 'manual',
      submittedAt: new Date().toISOString(),
      estimatedCompletion: estimatedCompletion.toISOString(),
      userData: { email: maskEmail(userData.email) }
    };

    optOutRequests.set(requestId, request);

    res.json({
      success: true,
      ...request,
      nextSteps: brokerInfo.optOut.instructions,
      trackingUrl: `/api/v2/footprint/optout-status/${requestId}`
    });

  } catch (error) {
    console.error('Opt-out Request Fehler:', error);
    res.status(500).json({
      error: 'Opt-out Request fehlgeschlagen',
      details: error.message
    });
  }
});

// GET /api/v2/footprint/optout-status/:requestId - Check opt-out status
app.get('/api/v2/footprint/optout-status/:requestId', (req, res) => {
  const { requestId } = req.params;

  const request = optOutRequests.get(requestId);
  if (!request) {
    return res.status(404).json({
      error: 'Request nicht gefunden'
    });
  }

  // Simulate status progression
  const elapsed = Date.now() - new Date(request.submittedAt).getTime();
  const hoursElapsed = elapsed / (1000 * 60 * 60);

  let status = request.status;
  if (hoursElapsed > 72) {
    status = 'completed';
  } else if (hoursElapsed > 24) {
    status = 'processing';
  } else if (hoursElapsed > 1) {
    status = 'pending_verification';
  }

  res.json({
    requestId,
    broker: request.broker,
    status,
    submittedAt: request.submittedAt,
    estimatedCompletion: request.estimatedCompletion,
    completedAt: status === 'completed' ? new Date().toISOString() : null,
    verified: status === 'completed',
    message: status === 'completed'
      ? 'Ihre Daten wurden erfolgreich entfernt'
      : status === 'processing'
      ? 'Ihre Anfrage wird bearbeitet'
      : 'Warten auf Verifikation'
  });
});

// GET /api/v2/footprint/databrokers - Data broker database
app.get('/api/v2/footprint/databrokers', (req, res) => {
  const { region, category, optout_difficulty } = req.query;

  let filtered = DATA_BROKERS;

  if (region) {
    filtered = filtered.filter(b => b.region === region || b.region === 'Global');
  }
  if (category) {
    filtered = filtered.filter(b => b.category === category);
  }
  if (optout_difficulty) {
    filtered = filtered.filter(b => b.optOut.difficulty === optout_difficulty);
  }

  // Get unique categories with counts
  const categories = {};
  DATA_BROKERS.forEach(b => {
    categories[b.category] = (categories[b.category] || 0) + 1;
  });

  const categoryList = Object.entries(categories).map(([id, count]) => ({
    id,
    name: {
      people_search: 'Personensuche',
      marketing_data: 'Marketing-Daten',
      background_check: 'Hintergrund-Checks',
      credit_reporting: 'Kredit-Auskunft',
      recruitment: 'Recruiting',
      insurance: 'Versicherung'
    }[id] || id,
    count
  }));

  res.json({
    success: true,
    totalBrokers: DATA_BROKERS.length,
    filteredCount: filtered.length,
    brokers: filtered.map(b => ({
      id: b.id,
      name: b.name,
      website: b.website,
      category: b.category,
      region: b.region,
      dataCollected: b.dataCollected,
      sources: b.sources,
      optOut: {
        available: b.optOut.available,
        url: b.optOut.url,
        difficulty: b.optOut.difficulty,
        gdprCompliant: b.optOut.gdprCompliant
      },
      riskLevel: b.riskLevel,
      description: b.description
    })),
    categories: categoryList
  });
});

// GET /api/v2/footprint/breach-database - Breach database
app.get('/api/v2/footprint/breach-database', (req, res) => {
  const { search, year, severity, limit = 50 } = req.query;

  let filtered = BREACH_DATABASE;

  if (search) {
    const searchLower = search.toLowerCase();
    filtered = filtered.filter(b =>
      b.name.toLowerCase().includes(searchLower) ||
      b.domain.toLowerCase().includes(searchLower)
    );
  }
  if (year) {
    filtered = filtered.filter(b => b.date.startsWith(year));
  }
  if (severity) {
    filtered = filtered.filter(b => b.severity === severity);
  }

  // Calculate stats
  const totalCompromised = BREACH_DATABASE.reduce((sum, b) => sum + b.compromisedAccounts, 0);

  const breachesByYear = {};
  BREACH_DATABASE.forEach(b => {
    const y = b.date.substring(0, 4);
    breachesByYear[y] = (breachesByYear[y] || 0) + 1;
  });

  const dataClassCounts = {};
  BREACH_DATABASE.forEach(b => {
    b.dataClasses.forEach(dc => {
      dataClassCounts[dc] = (dataClassCounts[dc] || 0) + 1;
    });
  });

  const topDataClasses = Object.entries(dataClassCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([type, count]) => ({ type, count }));

  res.json({
    success: true,
    totalBreaches: BREACH_DATABASE.length,
    filteredCount: filtered.length,
    breaches: filtered.slice(0, parseInt(limit)).map(b => ({
      id: b.id,
      name: b.name,
      domain: b.domain,
      date: b.date,
      addedDate: b.addedDate,
      compromisedAccounts: b.compromisedAccounts,
      dataClasses: b.dataClasses,
      description: b.description,
      severity: b.severity,
      isVerified: b.isVerified,
      isSensitive: b.isSensitive,
      affectedCountries: b.affectedCountries
    })),
    stats: {
      totalCompromisedAccounts: totalCompromised,
      breachesByYear,
      topDataClasses
    }
  });
});

// POST /api/v2/footprint/monitor - Set up monitoring (placeholder)
app.post('/api/v2/footprint/monitor', (req, res) => {
  const { email, notifyEmail, options = {} } = req.body;

  if (!email) {
    return res.status(400).json({
      error: 'Email-Adresse erforderlich'
    });
  }

  const monitorId = 'mon_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5);

  res.json({
    success: true,
    monitorId,
    email: maskEmail(email),
    status: 'pending_verification',
    features: {
      breachAlerts: options.breachAlerts !== false,
      darkWebMonitoring: options.darkWebMonitoring || false,
      socialMentions: options.socialMentions || false,
      databrokerAlerts: options.databrokerAlerts || false
    },
    verificationRequired: true,
    verificationSentTo: maskEmail(notifyEmail || email),
    message: 'Bitte bestätigen Sie Ihre Email-Adresse um das Monitoring zu aktivieren'
  });
});

// GET /api/v2/footprint/social-platforms - List supported social platforms
app.get('/api/v2/footprint/social-platforms', (req, res) => {
  res.json({
    success: true,
    totalPlatforms: SOCIAL_PLATFORMS.length,
    platforms: SOCIAL_PLATFORMS.map(p => ({
      id: p.id,
      displayName: p.displayName,
      domain: p.domain,
      usernameFormat: p.usernameFormat,
      publicDataFields: p.publicDataFields,
      privacySettings: p.privacySettings,
      riskLevel: p.riskLevel
    }))
  });
});

// ===========================================
// API v2 - Phase 10 Endpoints (Smart Privacy Coach)
// ===========================================

// POST /api/v2/coach/chat - Main chat interaction
app.post('/api/v2/coach/chat', (req, res) => {
  const { sessionId, message, context = {} } = req.body;

  if (!message) {
    return res.status(400).json({
      error: 'Nachricht erforderlich'
    });
  }

  // Get or create session
  const session = getOrCreateSession(sessionId, context.userProfile);

  // Add user message to history
  const userMessageId = generateMessageId();
  session.conversationHistory.push({
    id: userMessageId,
    role: 'user',
    content: message,
    timestamp: new Date().toISOString()
  });

  // Update context if previous analysis provided
  if (context.previousAnalysis) {
    session.context.lastAnalyzedText = context.previousAnalysis.text;
    session.context.lastAnalysisResults = context.previousAnalysis;
  }

  // Generate response
  const coachResponse = generateCoachResponse(message, context, session.userProfile);
  const responseMessageId = generateMessageId();

  // Add coach response to history
  session.conversationHistory.push({
    id: responseMessageId,
    role: 'coach',
    content: coachResponse.message,
    timestamp: new Date().toISOString(),
    messageType: coachResponse.messageType,
    metadata: {
      confidence: coachResponse.confidence,
      sources: coachResponse.sources || []
    }
  });

  // Generate suggestions based on context
  const suggestions = [];

  if (coachResponse.messageType === 'explanation') {
    suggestions.push({
      type: 'follow_up',
      text: 'Erzähl mir mehr darüber',
      action: 'ask'
    });
    suggestions.push({
      type: 'learn_more',
      text: 'Zeige verwandte Themen',
      action: 'topics'
    });
  }

  if (context.previousAnalysis && context.previousAnalysis.riskScore > 50) {
    suggestions.push({
      type: 'action',
      text: 'Text sicherer umschreiben',
      action: 'rewrite',
      params: { removeTypes: context.previousAnalysis.risks || [] }
    });
  }

  suggestions.push({
    type: 'follow_up',
    text: 'Was sollte ich noch wissen?',
    action: 'ask'
  });

  // Get a random privacy tip
  const randomTip = QUICK_TIPS[Math.floor(Math.random() * QUICK_TIPS.length)];

  res.json({
    success: true,
    sessionId: session.id,
    response: {
      message: coachResponse.message,
      messageType: coachResponse.messageType,
      confidence: coachResponse.confidence,
      sources: coachResponse.sources || []
    },
    suggestions: suggestions.slice(0, 3),
    relatedTopics: coachResponse.relatedTopics || [],
    privacyTip: {
      icon: randomTip.icon,
      text: randomTip.content
    }
  });
});

// POST /api/v2/coach/explain - Explain a privacy term
app.post('/api/v2/coach/explain', (req, res) => {
  const { term, complexity = 'simple', language = 'de', context } = req.body;

  if (!term) {
    return res.status(400).json({
      error: 'Begriff erforderlich'
    });
  }

  const normalizedTerm = term.toLowerCase().replace(/\s+/g, '-');

  // Check privacy terms
  const termData = PRIVACY_TERMS[normalizedTerm];

  if (!termData) {
    // Check risk type explanations
    const riskType = Object.entries(RISK_TYPE_EXPLANATIONS).find(([key, val]) =>
      key === normalizedTerm || val.name.toLowerCase() === term.toLowerCase()
    );

    if (riskType) {
      const [key, info] = riskType;
      return res.json({
        success: true,
        term: term,
        explanation: {
          simple: `${info.name}: ${info.risks[0]}`,
          detailed: `${info.name} ist ein sensibler Datentyp. Risiken: ${info.risks.join(', ')}. ${info.advice[0]}`,
          technical: `${info.name} (Severity: ${info.severity}). Angriffsvektoren: ${info.risks.join('; ')}. Mitigationsstrategien: ${info.advice.join('; ')}`
        },
        examples: info.risks.map((risk, i) => ({
          scenario: `Risiko ${i + 1}`,
          description: risk
        })),
        visualAid: {
          type: 'risk_level',
          data: {
            level: info.severity,
            icon: info.severity === 'critical' ? '🔴' : info.severity === 'high' ? '🟠' : '🟡'
          }
        },
        relatedTerms: Object.keys(RISK_TYPE_EXPLANATIONS).filter(k => k !== key).slice(0, 3),
        learnMore: {
          url: `/learn/${key}`
        }
      });
    }

    return res.status(404).json({
      error: 'Begriff nicht gefunden',
      suggestion: 'Versuche: ' + Object.keys(PRIVACY_TERMS).slice(0, 5).join(', ')
    });
  }

  // Build examples based on term
  let examples = [];
  if (normalizedTerm === 'k-anonymity') {
    examples = [
      { scenario: 'k=1 (schlecht)', description: 'Du bist der einzige 25-jährige Programmierer in Berlin-Mitte → sofort identifizierbar' },
      { scenario: 'k=1000 (gut)', description: 'Du bist einer von 1000 Personen mit gleichen Merkmalen → gut versteckt' }
    ];
  } else if (normalizedTerm === 'phishing') {
    examples = [
      { scenario: 'E-Mail-Phishing', description: 'Eine gefälschte E-Mail von "PayPal" fordert zur Passwort-Eingabe auf' },
      { scenario: 'Spear-Phishing', description: 'Eine E-Mail nennt deinen echten Namen und Arbeitgeber, um glaubwürdig zu wirken' }
    ];
  }

  res.json({
    success: true,
    term: term,
    explanation: {
      simple: termData.simple,
      detailed: termData.detailed,
      technical: termData.technical
    },
    examples,
    visualAid: normalizedTerm === 'k-anonymity' ? {
      type: 'comparison',
      data: [
        { k: 1, risk: 'critical', icon: '🔴' },
        { k: 10, risk: 'high', icon: '🟠' },
        { k: 100, risk: 'medium', icon: '🟡' },
        { k: 1000, risk: 'low', icon: '🟢' }
      ]
    } : null,
    relatedTerms: Object.keys(PRIVACY_TERMS).filter(t => t !== normalizedTerm).slice(0, 4),
    learnMore: {
      url: `/learn/${normalizedTerm}`
    }
  });
});

// POST /api/v2/coach/analyze-risk - Risk analysis with conversational explanation
app.post('/api/v2/coach/analyze-risk', (req, res) => {
  const { text, questionType = 'why_risky', detailLevel = 'comprehensive' } = req.body;

  if (!text) {
    return res.status(400).json({
      error: 'Text erforderlich'
    });
  }

  // Detect data types
  const detectedData = detectDataTypes(text);

  // Calculate risk score and identifiability
  let totalUniqueness = 0;
  const dataPoints = [];

  // Detect full name (simple heuristic)
  const nameMatch = text.match(/(?:ich bin|mein name ist|heisse|heiße)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)/i);
  if (nameMatch) {
    const contribution = calculateUniquenessContribution('full_name');
    totalUniqueness += contribution;
    dataPoints.push({
      type: 'full_name',
      value: nameMatch[1],
      risk: 'high',
      explanation: 'Dein vollständiger Name ist ein starker Identifikator',
      uniquenessContribution: contribution
    });
  }

  // Detect employer
  const employerMatch = text.match(/(?:arbeite bei|arbeite für|bin bei|bei der|bei)\s+([A-ZÄÖÜ][a-zäöüßA-ZÄÖÜ]+(?:\s+[A-ZÄÖÜ][a-zäöüßA-ZÄÖÜ]+)?)/i);
  if (employerMatch && !employerMatch[1].match(/^(der|die|das|einem|einer)$/i)) {
    const contribution = calculateUniquenessContribution('employer');
    totalUniqueness += contribution;
    dataPoints.push({
      type: 'employer',
      value: employerMatch[1],
      risk: 'medium',
      explanation: 'Eingrenzt dich auf Mitarbeiter eines bestimmten Unternehmens',
      uniquenessContribution: contribution
    });
  }

  // Add detected data types
  for (const data of detectedData) {
    const contribution = calculateUniquenessContribution(data.type);
    totalUniqueness += contribution;

    const riskInfo = RISK_TYPE_EXPLANATIONS[data.type] || { name: data.type, severity: data.risk };

    dataPoints.push({
      type: data.type,
      value: data.value,
      risk: data.risk,
      explanation: riskInfo.risks ? riskInfo.risks[0] : `${riskInfo.name} ist ein sensibler Datentyp`,
      uniquenessContribution: contribution
    });
  }

  // Calculate overall risk score
  const riskScore = Math.min(Math.round(totalUniqueness * 100), 100);
  const kAnonymity = riskScore > 90 ? 1 : riskScore > 70 ? 5 : riskScore > 50 ? 50 : riskScore > 30 ? 500 : 10000;
  const identifiability = kAnonymity === 1 ? 'unique' : kAnonymity < 10 ? 'highly_identifiable' : kAnonymity < 100 ? 'somewhat_identifiable' : 'anonymous';

  // Generate overall assessment
  let overallAssessment = '';
  if (riskScore > 80) {
    overallAssessment = 'Dieser Text enthält eine gefährliche Kombination von Daten, die dich eindeutig identifizierbar macht.';
  } else if (riskScore > 50) {
    overallAssessment = 'Dieser Text enthält mehrere sensible Daten, die in Kombination problematisch sein können.';
  } else if (riskScore > 20) {
    overallAssessment = 'Der Text enthält einige persönliche Informationen, die du möglicherweise schützen möchtest.';
  } else {
    overallAssessment = 'Der Text enthält wenig bis keine identifizierenden Informationen.';
  }

  // Build explanation
  let explanation = '';
  if (dataPoints.length > 0) {
    if (kAnonymity === 1) {
      explanation = `Mit diesen Informationen bist du **weltweit einzigartig identifizierbar**. Es gibt wahrscheinlich nur eine Person mit genau diesen Merkmalen.`;
    } else {
      explanation = `Diese Kombination von Daten grenzt dich auf ungefähr ${kAnonymity} Personen ein.`;
    }
  } else {
    explanation = 'Keine kritischen Datenpunkte erkannt.';
  }

  // Generate combination risk visualization
  const combinationFormula = dataPoints
    .map(dp => {
      const icon = dp.type === 'full_name' ? '👤' : dp.type === 'age' ? '🎂' : dp.type === 'address' ? '📍' :
                   dp.type === 'employer' ? '🏢' : dp.type === 'email' ? '📧' : dp.type === 'phone' ? '📱' : '📊';
      return icon;
    })
    .join(' + ');

  // Generate real-world threats
  const realWorldThreats = [];
  if (dataPoints.some(dp => dp.type === 'address')) {
    realWorldThreats.push({
      threat: 'Stalking',
      description: 'Jemand könnte dich physisch aufsuchen',
      likelihood: 'medium'
    });
  }
  if (dataPoints.some(dp => ['full_name', 'email', 'employer'].includes(dp.type))) {
    realWorldThreats.push({
      threat: 'Spear-Phishing',
      description: 'Gezielte Betrugs-Mails mit deinen echten Daten',
      likelihood: 'high'
    });
  }
  if (dataPoints.length >= 2) {
    realWorldThreats.push({
      threat: 'Identitätsdiebstahl',
      description: 'Jemand gibt sich als du aus',
      likelihood: riskScore > 70 ? 'high' : 'medium'
    });
  }

  // Generate recommendations
  const recommendations = dataPoints
    .filter(dp => dp.risk === 'critical' || dp.risk === 'high')
    .map((dp, i) => {
      let safeAlternative = '';
      switch(dp.type) {
        case 'address': safeAlternative = 'Erwähne nur die Stadt oder Region'; break;
        case 'full_name': safeAlternative = 'Nutze nur den Vornamen oder ein Pseudonym'; break;
        case 'employer': safeAlternative = 'Erwähne nur die Branche ("in der Automobilbranche")'; break;
        case 'phone': safeAlternative = 'Teile die Nummer nur privat per Nachricht'; break;
        case 'email': safeAlternative = 'Nutze eine Alias-Adresse'; break;
        case 'iban': safeAlternative = 'Teile Bankdaten niemals öffentlich'; break;
        default: safeAlternative = 'Entferne oder verallgemeinere diese Information';
      }
      return {
        priority: i + 1,
        action: `${RISK_TYPE_EXPLANATIONS[dp.type]?.name || dp.type} entfernen`,
        impact: `Reduziert Risiko um ${Math.round(dp.uniquenessContribution * 100)}%`,
        safeAlternative
      };
    });

  // Generate safe version of text
  let safeVersion = text;
  for (const dp of dataPoints) {
    if (dp.risk === 'critical' || dp.risk === 'high') {
      switch(dp.type) {
        case 'address':
          safeVersion = safeVersion.replace(new RegExp(dp.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '[Stadt]');
          break;
        case 'full_name':
          const firstName = dp.value.split(' ')[0];
          safeVersion = safeVersion.replace(dp.value, firstName);
          break;
        case 'employer':
          safeVersion = safeVersion.replace(new RegExp(`bei\\s+${dp.value}`, 'gi'), 'in der Branche');
          break;
        case 'phone':
          safeVersion = safeVersion.replace(new RegExp(dp.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[Telefon entfernt]');
          break;
        case 'iban':
          safeVersion = safeVersion.replace(new RegExp(dp.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[IBAN entfernt]');
          break;
        case 'email':
          safeVersion = safeVersion.replace(new RegExp(dp.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[E-Mail entfernt]');
          break;
      }
    }
  }

  const remainingRisk = Math.max(5, riskScore - recommendations.reduce((sum, r) => sum + parseInt(r.impact.match(/\d+/)?.[0] || 0), 0));

  res.json({
    success: true,
    analysis: {
      overallAssessment,
      riskScore,
      identifiability,
      kAnonymity,
      explanation
    },
    dataPoints,
    combinationRisk: {
      explanation: 'Die Kombination dieser Daten ist besonders gefährlich:',
      calculation: dataPoints.map(dp => `${RISK_TYPE_EXPLANATIONS[dp.type]?.name || dp.type} (${Math.round(dp.uniquenessContribution * 100)}%)`).join(' + '),
      visualFormula: combinationFormula + (dataPoints.length > 0 ? ` = ${riskScore > 80 ? '🎯 (eindeutig)' : riskScore > 50 ? '⚠️ (riskant)' : '✓ (okay)'}` : '')
    },
    realWorldThreats,
    recommendations,
    safeVersion: {
      text: safeVersion,
      remainingRisk,
      improvement: `Risiko von ${riskScore}% auf ${remainingRisk}% reduziert`
    }
  });
});

// GET /api/v2/coach/topics - List learning topics
app.get('/api/v2/coach/topics', (req, res) => {
  const featuredTopicIndex = Math.floor(Date.now() / (24 * 60 * 60 * 1000)) % 5;
  const allTopics = COACH_TOPICS.categories.flatMap(c => c.topics);
  const featuredTopic = allTopics[featuredTopicIndex % allTopics.length];

  res.json({
    success: true,
    categories: COACH_TOPICS.categories,
    featuredTopic: {
      id: featuredTopic.id,
      title: featuredTopic.title,
      description: featuredTopic.description,
      badge: 'Empfohlen'
    }
  });
});

// GET /api/v2/coach/topic/:topicId - Get topic details
app.get('/api/v2/coach/topic/:topicId', (req, res) => {
  const { topicId } = req.params;

  // Find topic in categories
  let topicMeta = null;
  for (const category of COACH_TOPICS.categories) {
    const found = category.topics.find(t => t.id === topicId);
    if (found) {
      topicMeta = found;
      break;
    }
  }

  if (!topicMeta) {
    return res.status(404).json({
      error: 'Thema nicht gefunden',
      availableTopics: COACH_TOPICS.categories.flatMap(c => c.topics.map(t => t.id))
    });
  }

  // Get content
  const content = TOPIC_CONTENT[topicId];

  if (!content) {
    // Return basic topic info without detailed content
    return res.json({
      success: true,
      topic: {
        id: topicMeta.id,
        title: topicMeta.title,
        icon: topicMeta.icon,
        difficulty: topicMeta.difficulty,
        duration: topicMeta.duration,
        lastUpdated: new Date().toISOString().split('T')[0]
      },
      content: {
        introduction: `${topicMeta.title} - ${topicMeta.description}. Detaillierte Inhalte werden bald verfügbar sein.`,
        sections: [],
        keyTakeaways: ['Weitere Informationen folgen'],
        relatedTopics: []
      },
      progress: {
        completed: false,
        percentComplete: 0
      }
    });
  }

  res.json({
    success: true,
    topic: {
      id: topicMeta.id,
      title: topicMeta.title,
      icon: topicMeta.icon,
      difficulty: topicMeta.difficulty,
      duration: topicMeta.duration,
      lastUpdated: new Date().toISOString().split('T')[0]
    },
    content: {
      introduction: content.introduction,
      sections: content.sections,
      keyTakeaways: content.keyTakeaways,
      relatedTopics: content.relatedTopics
    },
    progress: {
      completed: false,
      percentComplete: 0
    }
  });
});

// POST /api/v2/coach/session - Create or load session
app.post('/api/v2/coach/session', (req, res) => {
  const { action, sessionId, userProfile = {} } = req.body;

  if (action === 'load' && sessionId) {
    const session = coachSessions.get(sessionId);
    if (!session) {
      return res.status(404).json({
        error: 'Session nicht gefunden oder abgelaufen'
      });
    }

    session.lastActivity = new Date().toISOString();

    return res.json({
      success: true,
      session: {
        id: session.id,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        userProfile: session.userProfile,
        conversationHistory: session.conversationHistory,
        context: session.context
      }
    });
  }

  // Create new session
  const session = getOrCreateSession(null, userProfile);

  const lang = userProfile.language || 'de';
  const welcomeMessage = {
    message: COACH_TEMPLATES.greeting[lang] || COACH_TEMPLATES.greeting.de,
    suggestions: [
      { text: 'Was sind personenbezogene Daten?', action: 'ask' },
      { text: 'Analysiere meinen Text', action: 'analyze' },
      { text: 'Zeige mir Lern-Themen', action: 'topics' }
    ]
  };

  res.json({
    success: true,
    session: {
      id: session.id,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      userProfile: session.userProfile,
      conversationHistory: [],
      context: session.context
    },
    welcomeMessage
  });
});

// POST /api/v2/coach/feedback - Submit feedback
app.post('/api/v2/coach/feedback', (req, res) => {
  const { sessionId, messageId, rating, comment } = req.body;

  if (!rating) {
    return res.status(400).json({
      error: 'Bewertung erforderlich'
    });
  }

  const validRatings = ['helpful', 'not_helpful', 'incorrect', 'offensive'];
  if (!validRatings.includes(rating)) {
    return res.status(400).json({
      error: 'Ungültige Bewertung',
      validRatings
    });
  }

  // Store feedback (anonymized)
  coachFeedback.push({
    id: 'fb_' + Date.now().toString(36),
    timestamp: new Date().toISOString(),
    rating,
    hasComment: !!comment,
    commentLength: comment ? comment.length : 0
    // Note: We don't store sessionId, messageId, or actual comment content for privacy
  });

  // Keep only last 1000 feedback entries
  while (coachFeedback.length > 1000) {
    coachFeedback.shift();
  }

  const messages = {
    helpful: 'Danke für dein positives Feedback! Es hilft mir, besser zu werden.',
    not_helpful: 'Danke für dein Feedback. Ich werde versuchen, mich zu verbessern.',
    incorrect: 'Danke für die Korrektur! Ich lerne ständig dazu.',
    offensive: 'Danke für den Hinweis. Wir werden das überprüfen.'
  };

  res.json({
    success: true,
    message: messages[rating] || 'Danke für dein Feedback!'
  });
});

// GET /api/v2/coach/quick-tips - Get quick privacy tips
app.get('/api/v2/coach/quick-tips', (req, res) => {
  const { count = 2, category } = req.query;

  let filteredTips = QUICK_TIPS;
  if (category) {
    filteredTips = QUICK_TIPS.filter(t => t.category === category);
  }

  // Shuffle and pick tips
  const shuffled = [...filteredTips].sort(() => 0.5 - Math.random());
  const selectedTips = shuffled.slice(0, Math.min(parseInt(count), 5)).map(tip => ({
    id: tip.id,
    icon: tip.icon,
    title: tip.title,
    content: tip.content,
    category: tip.category,
    actionButton: {
      text: 'Mehr erfahren',
      action: 'topic',
      params: { topicId: tip.category }
    }
  }));

  // Get daily challenge
  const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / (24 * 60 * 60 * 1000));
  const dailyChallenge = DAILY_CHALLENGES[dayOfYear % DAILY_CHALLENGES.length];

  res.json({
    success: true,
    tips: selectedTips,
    dailyChallenge: {
      title: dailyChallenge.title,
      description: dailyChallenge.description,
      reward: dailyChallenge.reward,
      difficulty: dailyChallenge.difficulty
    }
  });
});

// ===========================================
// API v2 - Phase 11 Endpoints (Privacy Templates)
// ===========================================

// GET /api/v2/templates/categories - List all template categories
app.get('/api/v2/templates/categories', (req, res) => {
  const categories = TEMPLATE_CATEGORIES.map(cat => {
    const templateCount = PRIVACY_TEMPLATES.filter(t => t.category === cat.id).length;
    return {
      id: cat.id,
      name: cat.name,
      icon: cat.icon,
      description: cat.description,
      templateCount
    };
  });

  res.json({
    success: true,
    categories
  });
});

// GET /api/v2/templates/category/:categoryId - List templates in a category
app.get('/api/v2/templates/category/:categoryId', (req, res) => {
  const { categoryId } = req.params;
  const { subcategory, tag, sort = 'popularity' } = req.query;

  const category = TEMPLATE_CATEGORIES.find(c => c.id === categoryId);
  if (!category) {
    return res.status(404).json({
      error: 'Kategorie nicht gefunden',
      availableCategories: TEMPLATE_CATEGORIES.map(c => c.id)
    });
  }

  let templates = PRIVACY_TEMPLATES.filter(t => t.category === categoryId);

  // Filter by subcategory
  if (subcategory) {
    templates = templates.filter(t => t.subcategory === subcategory);
  }

  // Filter by tag
  if (tag) {
    templates = templates.filter(t => t.tags.includes(tag.toLowerCase()));
  }

  // Sort
  if (sort === 'popularity') {
    templates.sort((a, b) => b.popularity - a.popularity);
  } else if (sort === 'privacyScore') {
    templates.sort((a, b) => b.privacyScore - a.privacyScore);
  } else if (sort === 'name') {
    templates.sort((a, b) => a.name.localeCompare(b.name));
  }

  res.json({
    success: true,
    category: {
      id: category.id,
      name: category.name,
      icon: category.icon,
      subcategories: category.subcategories
    },
    templates: templates.map(t => ({
      id: t.id,
      name: t.name,
      description: t.description,
      privacyScore: t.privacyScore,
      popularity: t.popularity,
      tags: t.tags,
      preview: t.preview,
      subcategory: t.subcategory
    }))
  });
});

// GET /api/v2/templates/:templateId - Get specific template with variants
app.get('/api/v2/templates/:templateId', (req, res) => {
  const { templateId } = req.params;

  const template = PRIVACY_TEMPLATES.find(t => t.id === templateId);
  if (!template) {
    return res.status(404).json({
      error: 'Template nicht gefunden',
      availableTemplates: PRIVACY_TEMPLATES.map(t => t.id)
    });
  }

  res.json({
    success: true,
    template: {
      id: template.id,
      name: template.name,
      category: template.category,
      subcategory: template.subcategory,
      description: template.description,
      privacyScore: template.privacyScore,
      privacyAnalysis: template.privacyAnalysis,
      variants: template.variants,
      customizable: template.customizable,
      placeholders: template.placeholders,
      tips: template.tips,
      doNot: template.doNot
    }
  });
});

// POST /api/v2/templates/customize - Customize a template with user inputs
app.post('/api/v2/templates/customize', (req, res) => {
  const { templateId, variantId, customizations = {} } = req.body;

  if (!templateId) {
    return res.status(400).json({
      error: 'Template ID erforderlich'
    });
  }

  const template = PRIVACY_TEMPLATES.find(t => t.id === templateId);
  if (!template) {
    return res.status(404).json({
      error: 'Template nicht gefunden'
    });
  }

  // Find variant or use first one
  let variant = template.variants[0];
  if (variantId) {
    const found = template.variants.find(v => v.id === variantId);
    if (found) variant = found;
  }

  // Apply customizations
  let content = variant.content;
  for (const [key, value] of Object.entries(customizations)) {
    content = content.replace(new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), value);
  }

  // Calculate privacy score of customized content
  const privacyScore = calculateTemplatePrivacyScore(content);

  // Check for privacy warnings
  const privacyWarnings = [];
  const issues = analyzeTextForPrivacy(content);
  for (const issue of issues) {
    privacyWarnings.push({
      type: issue.type,
      found: issue.found,
      warning: issue.suggestion
    });
  }

  // Check if still has unfilled placeholders
  const hasUnfilledPlaceholders = /\{\{[A-Z_]+\}\}/.test(content);

  res.json({
    success: true,
    result: {
      content,
      privacyScore,
      privacyWarnings,
      copyReady: !hasUnfilledPlaceholders && privacyWarnings.length === 0,
      hasUnfilledPlaceholders
    }
  });
});

// POST /api/v2/templates/analyze - Analyze user text and suggest improvements
app.post('/api/v2/templates/analyze', (req, res) => {
  const { text, context = 'general' } = req.body;

  if (!text) {
    return res.status(400).json({
      error: 'Text erforderlich'
    });
  }

  // Calculate privacy score
  const privacyScore = calculateTemplatePrivacyScore(text, context);
  const grade = getPrivacyGrade(privacyScore);

  // Find issues
  const issues = analyzeTextForPrivacy(text, context);

  // Generate improved version
  const suggestedVersion = generateImprovedText(text, issues);
  const improvedScore = calculateTemplatePrivacyScore(suggestedVersion, context);

  res.json({
    success: true,
    analysis: {
      privacyScore,
      grade,
      issues: issues.map(issue => ({
        type: issue.type,
        found: issue.found,
        severity: issue.severity,
        suggestion: issue.suggestion
      })),
      suggestedVersion,
      improvedScore
    }
  });
});

// GET /api/v2/templates/gdpr/:requestType - Get GDPR request templates
app.get('/api/v2/templates/gdpr/:requestType', (req, res) => {
  const { requestType } = req.params;

  const validTypes = Object.keys(GDPR_TEMPLATES);
  if (!validTypes.includes(requestType)) {
    return res.status(404).json({
      error: 'Anfragetyp nicht gefunden',
      validTypes,
      typeDescriptions: {
        access: 'Auskunftsanfrage - Welche Daten werden gespeichert?',
        deletion: 'Löschungsantrag - Daten löschen lassen',
        rectification: 'Berichtigungsantrag - Falsche Daten korrigieren',
        portability: 'Datenübertragung - Daten in lesbarem Format erhalten',
        objection: 'Widerspruch - Datenverarbeitung widersprechen'
      }
    });
  }

  const template = GDPR_TEMPLATES[requestType];

  res.json({
    success: true,
    requestType,
    template: {
      subject: template.subject,
      body: template.body,
      placeholders: template.placeholders,
      legalBasis: template.legalBasis,
      responseDeadline: template.responseDeadline,
      tips: template.tips
    }
  });
});

// POST /api/v2/templates/favorite - Save template as favorite (anonymized)
app.post('/api/v2/templates/favorite', (req, res) => {
  const { templateId, sessionId, action = 'add' } = req.body;

  if (!templateId) {
    return res.status(400).json({
      error: 'Template ID erforderlich'
    });
  }

  const template = PRIVACY_TEMPLATES.find(t => t.id === templateId);
  if (!template) {
    return res.status(404).json({
      error: 'Template nicht gefunden'
    });
  }

  // Use anonymous session tracking
  const anonSession = sessionId || 'anon_' + Date.now().toString(36);

  if (!templateFavorites.has(anonSession)) {
    templateFavorites.set(anonSession, new Set());
  }

  const favorites = templateFavorites.get(anonSession);

  if (action === 'remove') {
    favorites.delete(templateId);
    return res.json({
      success: true,
      message: 'Template aus Favoriten entfernt',
      sessionId: anonSession,
      favoriteCount: favorites.size
    });
  }

  favorites.add(templateId);

  // Limit favorites per session
  if (favorites.size > 50) {
    const oldest = favorites.values().next().value;
    favorites.delete(oldest);
  }

  // Update popularity (anonymized)
  template.popularity = (template.popularity || 0) + 1;

  res.json({
    success: true,
    message: 'Template zu Favoriten hinzugefügt',
    sessionId: anonSession,
    favoriteCount: favorites.size
  });
});

// GET /api/v2/templates/favorites - Get favorites for a session
app.get('/api/v2/templates/favorites', (req, res) => {
  const { sessionId } = req.query;

  if (!sessionId || !templateFavorites.has(sessionId)) {
    return res.json({
      success: true,
      favorites: []
    });
  }

  const favoriteIds = Array.from(templateFavorites.get(sessionId));
  const favorites = favoriteIds
    .map(id => PRIVACY_TEMPLATES.find(t => t.id === id))
    .filter(Boolean)
    .map(t => ({
      id: t.id,
      name: t.name,
      category: t.category,
      description: t.description,
      privacyScore: t.privacyScore,
      preview: t.preview
    }));

  res.json({
    success: true,
    favorites
  });
});

// GET /api/v2/templates/search - Search templates
app.get('/api/v2/templates/search', (req, res) => {
  const { q, category, minScore, maxResults = 10 } = req.query;

  if (!q || q.length < 2) {
    return res.status(400).json({
      error: 'Suchbegriff muss mindestens 2 Zeichen haben'
    });
  }

  const query = q.toLowerCase();
  let results = PRIVACY_TEMPLATES.filter(t => {
    const searchable = `${t.name} ${t.description} ${t.tags.join(' ')} ${t.preview}`.toLowerCase();
    return searchable.includes(query);
  });

  // Filter by category
  if (category) {
    results = results.filter(t => t.category === category);
  }

  // Filter by minimum privacy score
  if (minScore) {
    const minScoreNum = parseInt(minScore);
    results = results.filter(t => t.privacyScore >= minScoreNum);
  }

  // Sort by relevance (name match first, then popularity)
  results.sort((a, b) => {
    const aNameMatch = a.name.toLowerCase().includes(query) ? 1 : 0;
    const bNameMatch = b.name.toLowerCase().includes(query) ? 1 : 0;
    if (aNameMatch !== bNameMatch) return bNameMatch - aNameMatch;
    return b.popularity - a.popularity;
  });

  // Limit results
  results = results.slice(0, parseInt(maxResults));

  res.json({
    success: true,
    query: q,
    resultCount: results.length,
    results: results.map(t => ({
      id: t.id,
      name: t.name,
      category: t.category,
      description: t.description,
      privacyScore: t.privacyScore,
      tags: t.tags,
      preview: t.preview
    }))
  });
});

// Server starten
app.listen(PORT, () => {
  console.log(`achtung.live API läuft auf Port ${PORT}`);
});
