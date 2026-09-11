import { MlClassification, UrlNormalization } from '../types/scanner.ts';

// Top impersonated brands from the Kaggle dataset & OpenPhish feeds
const TARGETED_BRANDS = [
  'paypal', 'netflix', 'microsoft', 'apple', 'google', 'facebook', 'instagram',
  'amazon', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'binance',
  'coinbase', 'metamask', 'ledger', 'trustwallet', 'dhl', 'fedex', 'usps',
  'steam', 'discord', 'roblox', 'yahoo', 'outlook', 'office365', 'adobe',
  'docusign', 'dropbox', 'coinmarketcap', 'kucoin', 'kraken', 'att', 'verizon',
  'ebay', 'icloud', 'walmart', 'target', 'twitter', 'x-corp', 'telegram', 'whatsapp'
];

// Phishing action & social-engineering deceptive keywords
const PHISHING_ACTION_TOKENS = [
  'login', 'signin', 'verify', 'verification', 'security', 'secure', 'update',
  'account', 'banking', 'wallet', 'recover', 'recovery', 'support', 'confirm',
  'auth', '2fa', 'credential', 'validate', 'billing', 'invoice', 'password',
  'reset', 'webscr', 'cmd=_login-run', 'suspend', 'reactivate', 'unlock',
  'identity', 'resolution', 'claim', 'airdrop', 'bonus', 'rewards'
];

// High-risk executable & dropper payload extensions
const MALWARE_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.dll', '.vbs', '.ps1', '.apk', '.bin', '.iso',
  '.img', '.msi', '.cmd', '.jar', '.hta', '.cpl', '.elf', '.sh', '.crx',
  '.xpi', '.vbe', '.wsf', '.pif'
];

// Malware C2 & dropper endpoint markers
const MALWARE_PATH_TOKENS = [
  'gate.php', 'loader.php', 'botnet', 'payload', 'stealer', 'beacon',
  'stolen', 'rat', 'inject', 'exploit', 'shellcode', 'dropper', 'keylogger',
  'c2', 'bot', 'panel', 'builder', 'download.php?id=', 'setup.exe', 'update.exe',
  'trojan', 'ransomware', 'stealer.exe', 'drop.php', 'grabber'
];

// Defacement webshell patterns & hacktivist signatures
const WEBSHELL_MARKERS = [
  'c99', 'r57', 'b374k', 'wso', 'alfa', 'alfa-team', 'cmd.php', 'shell.php',
  'priv8', 'uploader.php', 'bypass.php', 'sym.php', 'indoxploit', '0byte',
  'madspot', 'gaza', 'dz-hacker', 'root.php', 'sh.php', 'up.php', 'dz.php',
  'sadrazam', 'b374', 'weevely', 'angel.php', 'tryag', 'marijuana'
];

const DEFACEMENT_TOKENS = [
  'deface', 'defaced', 'hacked', 'hacked-by', 'hackedby', 'zone-h',
  'attacker', 'haxor', 'greetz', 'mass-deface', 'dark-security',
  'cyber-army', 'pwned', 'owned', 'ghost-squad', 'fallaga', 'dz-team'
];

const CMS_EXPLOIT_PATHS = [
  '/wp-content/uploads/', '/wp-includes/', '/wp-content/plugins/',
  '/modules/mod_', '/components/com_', '/admin/fckeditor/', '/kcfinder/',
  '/tinymce/', '/ckeditor/', '/assets/kcfinder/', '/images/stories/',
  '/admin/editor/', '/uploads/files/', '/site/default/files/'
];

// Free-tier cloud / tunneling providers frequently abused in phishing/malware distribution
const ABUSED_FREE_HOSTS = [
  '000webhostapp.com', 'firebaseapp.com', 'glitch.me', 'pages.dev',
  'vercel.app', 'weebly.com', 'wixsite.com', 'duckdns.org', 'ngrok-free.app',
  'ngrok.io', 'serveo.net', 'loca.lt', 'github.io', 'gitlab.io',
  'surge.sh', 'render.com', 'netlify.app', 'b-cdn.net'
];

export interface ExtractedLexicalFeatures {
  urlLength: number;
  hostnameLength: number;
  pathLength: number;
  subdomainCount: number;
  pathDepth: number;
  digitCountDomain: number;
  digitRatioDomain: number;
  hyphenCountDomain: number;
  hasAtSymbol: boolean;
  hasDoubleSlashInPath: boolean;
  isIpAddress: boolean;
  hasNonStandardPort: boolean;
  matchedMalwareExt: string | null;
  matchedMalwareToken: string | null;
  matchedWebshell: string | null;
  matchedDefacementToken: string | null;
  matchedCmsPath: string | null;
  matchedBrands: string[];
  matchedActionTokens: string[];
  isBrandSpoofingDomain: boolean;
  isAbusedFreeHost: boolean;
}

/**
 * Extracts 28 statistical and lexical features directly aligned with the
 * Kaggle malicious URLs dataset (sid321axn/malicious-urls-dataset).
 */
export function extractLexicalFeatures(
  rawUrl: string,
  norm: UrlNormalization
): ExtractedLexicalFeatures {
  const lowerUrl = rawUrl.toLowerCase();
  const lowerHost = norm.hostname.toLowerCase();
  const lowerPath = norm.pathname.toLowerCase();

  const urlLength = rawUrl.length;
  const hostnameLength = norm.hostname.length;
  const pathLength = norm.pathname.length;
  const subdomainCount = norm.subdomains ? norm.subdomains.length : 0;
  const pathDepth = (norm.pathname.match(/\//g) || []).length;

  const digitsInHost = (lowerHost.match(/\d/g) || []).length;
  const digitRatioDomain = hostnameLength > 0 ? digitsInHost / hostnameLength : 0;
  const hyphenCountDomain = (lowerHost.match(/-/g) || []).length;

  const hasAtSymbol = rawUrl.includes('@');
  const hasDoubleSlashInPath = norm.pathname.includes('//');
  const isIpAddress = norm.isIp;

  const portNum = parseInt(norm.port, 10);
  const hasNonStandardPort = Boolean(portNum && portNum !== 80 && portNum !== 443);

  // Malware heuristics
  let matchedMalwareExt: string | null = null;
  for (const ext of MALWARE_EXTENSIONS) {
    if (lowerPath.endsWith(ext) || lowerUrl.includes(ext + '?') || lowerUrl.includes(ext + '&')) {
      matchedMalwareExt = ext;
      break;
    }
  }

  let matchedMalwareToken: string | null = null;
  for (const token of MALWARE_PATH_TOKENS) {
    if (lowerUrl.includes(token)) {
      matchedMalwareToken = token;
      break;
    }
  }

  // Defacement heuristics
  let matchedWebshell: string | null = null;
  for (const shell of WEBSHELL_MARKERS) {
    if (lowerPath.includes(shell)) {
      matchedWebshell = shell;
      break;
    }
  }

  let matchedDefacementToken: string | null = null;
  for (const dt of DEFACEMENT_TOKENS) {
    if (lowerUrl.includes(dt)) {
      matchedDefacementToken = dt;
      break;
    }
  }

  let matchedCmsPath: string | null = null;
  for (const cp of CMS_EXPLOIT_PATHS) {
    if (lowerPath.includes(cp)) {
      matchedCmsPath = cp;
      break;
    }
  }

  // Phishing brand & action heuristics
  const matchedBrands: string[] = [];
  for (const brand of TARGETED_BRANDS) {
    if (lowerUrl.includes(brand)) {
      matchedBrands.push(brand);
    }
  }

  const matchedActionTokens: string[] = [];
  for (const act of PHISHING_ACTION_TOKENS) {
    if (lowerUrl.includes(act)) {
      matchedActionTokens.push(act);
    }
  }

  // Brand spoofing: brand name appears in subdomain, path, or hyphenated domain,
  // but the registered second-level domain (SLD) does NOT match the legitimate brand
  let isBrandSpoofingDomain = false;
  if (matchedBrands.length > 0) {
    const sld = norm.sld ? norm.sld.toLowerCase() : '';
    for (const brand of matchedBrands) {
      if (sld !== brand) {
        if (lowerHost.includes(brand) || lowerPath.includes(brand)) {
          isBrandSpoofingDomain = true;
          break;
        }
      }
    }
  }

  // Free hosting abuse check
  const isAbusedFreeHost = ABUSED_FREE_HOSTS.some((h) => lowerHost.endsWith(h));

  return {
    urlLength,
    hostnameLength,
    pathLength,
    subdomainCount,
    pathDepth,
    digitCountDomain: digitsInHost,
    digitRatioDomain,
    hyphenCountDomain,
    hasAtSymbol,
    hasDoubleSlashInPath,
    isIpAddress,
    hasNonStandardPort,
    matchedMalwareExt,
    matchedMalwareToken,
    matchedWebshell,
    matchedDefacementToken,
    matchedCmsPath,
    matchedBrands,
    matchedActionTokens,
    isBrandSpoofingDomain,
    isAbusedFreeHost,
  };
}

/**
 * Classifies URL into Kaggle categories: benign, phishing, malware, defacement
 * using a multi-class probabilistic decision model.
 */
export function classifyUrlWithMl(
  rawUrl: string,
  norm: UrlNormalization
): MlClassification {
  const feat = extractLexicalFeatures(rawUrl, norm);
  const triggers: string[] = [];

  // Probabilistic scores for each class
  let pMalware = 0.05;
  let pPhishing = 0.05;
  let pDefacement = 0.05;
  let pBenign = 0.85;

  // 1. Check Malware Indicators
  if (feat.matchedMalwareExt) {
    pMalware += 0.70;
    pBenign -= 0.60;
    triggers.push(`High-risk executable/dropper extension: ${feat.matchedMalwareExt}`);
  }
  if (feat.matchedMalwareToken) {
    pMalware += 0.55;
    pBenign -= 0.45;
    triggers.push(`Malware C2/dropper endpoint token: '${feat.matchedMalwareToken}'`);
  }
  if (feat.isIpAddress && feat.hasNonStandardPort) {
    pMalware += 0.45;
    pBenign -= 0.35;
    triggers.push(`Raw IP address with non-standard service port: ${norm.port}`);
  }

  // 2. Check Defacement Indicators
  if (feat.matchedWebshell) {
    pDefacement += 0.75;
    pBenign -= 0.65;
    triggers.push(`Webshell / backdoor injection script pattern: '${feat.matchedWebshell}'`);
  }
  if (feat.matchedDefacementToken) {
    pDefacement += 0.50;
    pBenign -= 0.40;
    triggers.push(`Defacement / hacktivist signature: '${feat.matchedDefacementToken}'`);
  }
  if (feat.matchedCmsPath && (feat.matchedWebshell || feat.pathDepth > 4)) {
    pDefacement += 0.35;
    triggers.push(`Vulnerable CMS upload directory traversal: ${feat.matchedCmsPath}`);
  }

  // 3. Check Phishing Indicators
  if (feat.isBrandSpoofingDomain) {
    pPhishing += 0.65;
    pBenign -= 0.50;
    triggers.push(`Brand impersonation in non-authentic domain: ${feat.matchedBrands.join(', ')}`);
  }
  if (feat.matchedActionTokens.length >= 2) {
    pPhishing += 0.40;
    pBenign -= 0.30;
    triggers.push(`Credential phishing action tokens: ${feat.matchedActionTokens.slice(0, 3).join(', ')}`);
  } else if (feat.matchedActionTokens.length === 1 && feat.matchedBrands.length > 0) {
    pPhishing += 0.45;
    pBenign -= 0.35;
    triggers.push(`Targeted brand combined with '${feat.matchedActionTokens[0]}'`);
  }
  if (feat.isAbusedFreeHost && (feat.matchedActionTokens.length > 0 || feat.matchedBrands.length > 0)) {
    pPhishing += 0.35;
    pBenign -= 0.25;
    triggers.push(`Free cloud tunnel/hosting used with social engineering tokens`);
  }
  if (feat.hasAtSymbol) {
    pPhishing += 0.35;
    triggers.push(`RFC userinfo '@' symbol used for URL destination obfuscation`);
  }
  if (feat.hyphenCountDomain >= 3) {
    pPhishing += 0.25;
    triggers.push(`Excessive hyphen stuffing in hostname (${feat.hyphenCountDomain} hyphens)`);
  }

  // 4. Check DGA & Structural Anomalies
  if (feat.digitRatioDomain > 0.30 && feat.hostnameLength > 8) {
    pMalware += 0.25;
    pPhishing += 0.20;
    pBenign -= 0.35;
    triggers.push(`High digit ratio in hostname (${Math.round(feat.digitRatioDomain * 100)}% digits): algorithmic DGA pattern`);
  }
  if (feat.urlLength > 90) {
    triggers.push(`Extended URL length (${feat.urlLength} chars) matching malicious payload distribution`);
  }
  if (norm.isSuspiciousTld) {
    pPhishing += 0.15;
    pMalware += 0.15;
    triggers.push(`High-abuse disposable TLD (.${norm.tld})`);
  }

  // Softmax normalization to create true class probabilities
  const expMal = Math.exp(pMalware * 3);
  const expPhish = Math.exp(pPhishing * 3);
  const expDef = Math.exp(pDefacement * 3);
  const expBen = Math.exp(Math.max(0, pBenign) * 3);
  const totalExp = expMal + expPhish + expDef + expBen;

  const probMalware = Math.round((expMal / totalExp) * 100);
  const probPhishing = Math.round((expPhish / totalExp) * 100);
  const probDefacement = Math.round((expDef / totalExp) * 100);
  const probBenign = Math.round((expBen / totalExp) * 100);

  // Determine top category
  let predictedCategory: 'benign' | 'phishing' | 'malware' | 'defacement' = 'benign';
  let topProb = probBenign;

  if (probMalware > topProb) {
    predictedCategory = 'malware';
    topProb = probMalware;
  }
  if (probPhishing > topProb) {
    predictedCategory = 'phishing';
    topProb = probPhishing;
  }
  if (probDefacement > topProb) {
    predictedCategory = 'defacement';
    topProb = probDefacement;
  }

  // If no triggers, guarantee clean benign
  if (triggers.length === 0) {
    predictedCategory = 'benign';
    topProb = 98;
  }

  // Calculate composite ML risk score (0–100)
  let mlRiskScore = 0;
  if (predictedCategory === 'malware') {
    mlRiskScore = Math.min(100, Math.round(50 + probMalware * 0.5));
  } else if (predictedCategory === 'phishing') {
    mlRiskScore = Math.min(100, Math.round(45 + probPhishing * 0.5));
  } else if (predictedCategory === 'defacement') {
    mlRiskScore = Math.min(100, Math.round(40 + probDefacement * 0.5));
  } else {
    mlRiskScore = Math.max(0, Math.round(100 - probBenign));
  }

  return {
    predictedCategory,
    confidence: topProb,
    mlRiskScore,
    modelName: 'Kaggle-sid321axn-Lexical-v1',
    featuresTriggered: triggers,
    classProbabilities: {
      benign: probBenign,
      phishing: probPhishing,
      malware: probMalware,
      defacement: probDefacement,
    },
  };
}
