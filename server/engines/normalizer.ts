import punycode from 'node:punycode';
import {
  UrlNormalization,
  HomoglyphAnalysis,
  HomoglyphCharacter,
  EntropyAnalysis,
} from '../types/scanner.ts';

// Known confusable mappings (Cyrillic, Greek, lookalikes -> Latin)
const CONFUSABLE_MAP: Record<string, { latin: string; name: string }> = {
  // Cyrillic small
  '\u0430': { latin: 'a', name: 'Cyrillic Small Letter A' },
  '\u0435': { latin: 'e', name: 'Cyrillic Small Letter Ie' },
  '\u043E': { latin: 'o', name: 'Cyrillic Small Letter O' },
  '\u0440': { latin: 'p', name: 'Cyrillic Small Letter Er' },
  '\u0441': { latin: 'c', name: 'Cyrillic Small Letter Es' },
  '\u0443': { latin: 'y', name: 'Cyrillic Small Letter U' },
  '\u0445': { latin: 'x', name: 'Cyrillic Small Letter Ha' },
  '\u0456': { latin: 'i', name: 'Cyrillic Small Letter Byelorussian-Ukrainian I' },
  '\u0458': { latin: 'j', name: 'Cyrillic Small Letter Je' },
  '\u0455': { latin: 's', name: 'Cyrillic Small Letter Dze' },
  '\u04CF': { latin: 'l', name: 'Cyrillic Small Letter Palochka' },
  // Cyrillic capital
  '\u0410': { latin: 'A', name: 'Cyrillic Capital Letter A' },
  '\u0412': { latin: 'B', name: 'Cyrillic Capital Letter Ve' },
  '\u0415': { latin: 'E', name: 'Cyrillic Capital Letter Ie' },
  '\u041A': { latin: 'K', name: 'Cyrillic Capital Letter Ka' },
  '\u041C': { latin: 'M', name: 'Cyrillic Capital Letter Em' },
  '\u041D': { latin: 'H', name: 'Cyrillic Capital Letter En' },
  '\u041E': { latin: 'O', name: 'Cyrillic Capital Letter O' },
  '\u0420': { latin: 'P', name: 'Cyrillic Capital Letter Er' },
  '\u0421': { latin: 'C', name: 'Cyrillic Capital Letter Es' },
  '\u0422': { latin: 'T', name: 'Cyrillic Capital Letter Te' },
  '\u0425': { latin: 'X', name: 'Cyrillic Capital Letter Ha' },
  // Greek
  '\u03BF': { latin: 'o', name: 'Greek Small Letter Omicron' },
  '\u03BD': { latin: 'v', name: 'Greek Small Letter Nu' },
  '\u03C1': { latin: 'p', name: 'Greek Small Letter Rho' },
};

// Major targeted brands for homograph attacks
const TARGETED_BRANDS = [
  'paypal',
  'microsoft',
  'google',
  'apple',
  'amazon',
  'netflix',
  'steam',
  'chase',
  'bankofamerica',
  'wellsfargo',
  'facebook',
  'instagram',
  'twitter',
  'telegram',
  'whatsapp',
  'binance',
  'coinbase',
  'github',
  'gitlab',
  'dropbox',
  'adobe',
  'linkedin',
  'outlook',
  'office365',
];

// Suspicious / high-abuse TLDs
const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'ru',
  'su',
  'cc',
  'buzz',
  'club',
  'work',
  'click',
  'link',
  'live',
  'loan',
  'date',
  'download',
  'win',
  'bid',
  'stream',
  'racing',
  'accountant',
  'faith',
  'cricket',
  'party',
  'science',
]);

/**
 * Refangs defanged URL representations into standard URL syntax
 */
export function refangUrl(rawUrl: string): string {
  let cleaned = rawUrl.trim();

  // Replace scheme defangs: hxxp:// -> http://, hxxps:// -> https://, meip://, etc.
  cleaned = cleaned.replace(/^hxxp:\/\//i, 'http://');
  cleaned = cleaned.replace(/^hxxps:\/\//i, 'https://');
  cleaned = cleaned.replace(/^fxp:\/\//i, 'ftp://');
  cleaned = cleaned.replace(/^fxps:\/\//i, 'ftps://');

  // Replace dot defang formats: [.] , (.) , {.} , [dot] , (dot)
  cleaned = cleaned.replace(/\[\.\]/g, '.');
  cleaned = cleaned.replace(/\(\.\)/g, '.');
  cleaned = cleaned.replace(/\{\.\}/g, '.');
  cleaned = cleaned.replace(/\[dot\]/gi, '.');
  cleaned = cleaned.replace(/\(dot\)/gi, '.');

  // Replace colon defang: [:]
  cleaned = cleaned.replace(/\[:\]/g, ':');
  cleaned = cleaned.replace(/\(:\)/g, ':');

  // If no scheme provided, default to http://
  if (!/^https?:\/\//i.test(cleaned) && !/^ftp:\/\//i.test(cleaned)) {
    cleaned = 'http://' + cleaned;
  }

  return cleaned;
}

/**
 * Defangs normal URL into safe analyst representation
 */
export function defangUrl(url: string): string {
  let defanged = url.trim();
  defanged = defanged.replace(/^http:\/\//i, 'hxxp://');
  defanged = defanged.replace(/^https:\/\//i, 'hxxps://');
  defanged = defanged.replace(/^ftp:\/\//i, 'fxp://');
  defanged = defanged.replace(/^ftps:\/\//i, 'fxps://');
  defanged = defanged.replace(/\./g, '[.]');
  return defanged;
}

/**
 * Calculates Shannon Entropy for a given string:
 * H(X) = - sum(P(x) * log2(P(x)))
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  const length = str.length;
  let entropy = 0;

  for (const char in frequencies) {
    const p = frequencies[char] / length;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * 1000) / 1000;
}

/**
 * Inspects hostname for Cyrillic / Unicode Punycode homographs and brand spoofing
 */
export function analyzeHomoglyphs(hostname: string): HomoglyphAnalysis {
  let decodedHost = hostname.toLowerCase();
  let isPunycode = false;

  // Handle Punycode domains: xn--...
  if (hostname.includes('xn--')) {
    isPunycode = true;
    try {
      // Decode punycode using node:punycode
      decodedHost = punycode.toUnicode(hostname);
    } catch {
      // fallback
    }
  }

  const details: HomoglyphCharacter[] = [];
  let normalizedAsciiCandidate = '';

  for (let i = 0; i < decodedHost.length; i++) {
    const char = decodedHost[i];
    if (CONFUSABLE_MAP[char]) {
      const entry = CONFUSABLE_MAP[char];
      details.push({
        char,
        index: i,
        unicode: `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`,
        latinEquivalent: entry.latin,
        description: entry.name,
      });
      normalizedAsciiCandidate += entry.latin;
    } else {
      normalizedAsciiCandidate += char;
    }
  }

  const hasHomoglyphs = details.length > 0;
  let spoofedBrand: string | undefined;

  // Check if replacing homoglyphs mimics a known brand
  for (const brand of TARGETED_BRANDS) {
    if (normalizedAsciiCandidate.includes(brand) && !decodedHost.includes(brand)) {
      spoofedBrand = brand;
      break;
    }
  }

  let riskLevel: 'clean' | 'suspicious' | 'critical' = 'clean';
  let explanation = 'No deceptive Unicode or homoglyph characters detected.';

  if (hasHomoglyphs) {
    if (spoofedBrand) {
      riskLevel = 'critical';
      explanation = `CRITICAL HOMOGRAPH ATTACK: Hostname utilizes Cyrillic/Unicode characters spoofing the '${spoofedBrand.toUpperCase()}' brand.`;
    } else {
      riskLevel = 'suspicious';
      explanation = `Suspicious non-ASCII / Cyrillic confusable characters detected in domain label (${details.length} characters).`;
    }
  }

  return {
    hasHomoglyphs,
    punycode: hostname,
    isPunycodeEncoded: isPunycode,
    spoofedBrand,
    riskLevel,
    details,
    explanation,
  };
}

/**
 * Evaluates Shannon Entropy across URL components
 */
export function analyzeEntropy(pathname: string, query: string, fullUrl: string): EntropyAnalysis {
  const pathEntropy = calculateShannonEntropy(pathname);
  const queryEntropy = calculateShannonEntropy(query);
  const fullUrlEntropy = calculateShannonEntropy(fullUrl);

  const analysisNotes: string[] = [];
  let isHighEntropy = false;
  let riskLevel: 'clean' | 'suspicious' | 'high' = 'clean';

  if (queryEntropy > 4.5 && query.length > 20) {
    isHighEntropy = true;
    riskLevel = 'high';
    analysisNotes.push(`High query entropy (${queryEntropy}): Potential Base64/encrypted payload, token or C2 beacon.`);
  } else if (queryEntropy > 4.0 && query.length > 15) {
    analysisNotes.push(`Elevated query entropy (${queryEntropy}): Parameter contains randomized or encoded token.`);
    if (riskLevel === 'clean') riskLevel = 'suspicious';
  }

  if (pathEntropy > 4.2 && pathname.length > 20) {
    isHighEntropy = true;
    if (riskLevel !== 'high') riskLevel = 'suspicious';
    analysisNotes.push(`Elevated path entropy (${pathEntropy}): Obfuscated endpoint or randomized URI segment.`);
  }

  if (fullUrlEntropy > 4.6) {
    analysisNotes.push(`High aggregate URL entropy (${fullUrlEntropy}).`);
  }

  if (analysisNotes.length === 0) {
    analysisNotes.push('Entropy within normal expected alphanumeric distribution.');
  }

  return {
    pathEntropy,
    queryEntropy,
    fullUrlEntropy,
    isHighEntropy,
    riskLevel,
    analysisNotes,
  };
}

/**
 * Normalizes input URL and extracts metadata
 */
export function normalizeUrl(input: string): UrlNormalization {
  const refanged = refangUrl(input);

  let parsed: URL;
  try {
    parsed = new URL(refanged);
  } catch {
    // If parsing failed, retry with http:// prefix
    parsed = new URL('http://' + refanged);
  }

  const hostname = parsed.hostname.toLowerCase();
  const defanged = defangUrl(parsed.href);

  // Check IP address
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') || hostname.includes(':');
  const isIp = isIpv4 || isIpv6;

  // Split domain parts
  const parts = hostname.split('.');
  let tld = '';
  let sld = '';
  const subdomains: string[] = [];

  if (!isIp && parts.length > 1) {
    tld = parts[parts.length - 1];
    sld = parts[parts.length - 2];
    if (parts.length > 2) {
      subdomains.push(...parts.slice(0, parts.length - 2));
    }
  } else if (isIp) {
    sld = hostname;
  } else {
    sld = hostname;
  }

  const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld.toLowerCase());

  return {
    originalUrl: input,
    canonicalUrl: parsed.href,
    defangedUrl: defanged,
    scheme: parsed.protocol.replace(':', ''),
    hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
    pathname: parsed.pathname,
    query: parsed.search,
    hash: parsed.hash,
    isIp,
    ipVersion: isIpv4 ? 'v4' : isIpv6 ? 'v6' : undefined,
    tld,
    sld,
    subdomains,
    isSuspiciousTld,
  };
}
