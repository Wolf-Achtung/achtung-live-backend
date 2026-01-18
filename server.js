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
    version: '4.0.0',
    features: ['quickCheck', 'batchAnalysis', 'smartRewrite', 'providerFallback', 'multiLanguage', 'offlinePatterns'],
    languages: SUPPORTED_LANGUAGES,
    endpoints: {
      v1: ['/analyze', '/rewrite', '/howto'],
      v2: ['/api/v2/analyze', '/api/v2/rewrite', '/api/v2/analyze/batch', '/api/v2/categories', '/api/v2/patterns', '/api/v2/health', '/api/v2/languages', '/api/v2/ping', '/api/v2/patterns/offline']
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
    version: '4.0.0',
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
    pwa: {
      offlinePatternsEndpoint: '/api/v2/patterns/offline',
      pingEndpoint: '/api/v2/ping'
    },
    rateLimits: {
      quickCheck: '60/min (recommended)',
      fullAnalysis: '10/min (recommended)'
    },
    endpoints: {
      v1: ['/analyze', '/rewrite', '/howto'],
      v2: ['/api/v2/analyze', '/api/v2/rewrite', '/api/v2/analyze/batch', '/api/v2/categories', '/api/v2/patterns', '/api/v2/health', '/api/v2/languages', '/api/v2/ping', '/api/v2/patterns/offline']
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
    version: '4.0',
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
    version: '4.0.0',
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

// Server starten
app.listen(PORT, () => {
  console.log(`achtung.live API läuft auf Port ${PORT}`);
});
