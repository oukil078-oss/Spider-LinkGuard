import { normalizeUrl, analyzeHomoglyphs, analyzeEntropy, defangUrl, refangUrl } from '../engines/normalizer.ts';
import { calculateThreatScore } from '../engines/scoringMatrix.ts';
import { generateDetectionRules } from '../engines/ruleExporter.ts';

console.log('--- Testing Engine 1: Normalizer & Heuristics ---');

// Test 1: Defang / Refang
const rawDefanged = 'hxxps://evil[.]com/login?token=abc';
const refanged = refangUrl(rawDefanged);
console.log(`Refanged '${rawDefanged}' -> '${refanged}'`);
if (refanged !== 'https://evil.com/login?token=abc') {
  throw new Error(`Refanging failed: expected 'https://evil.com/login?token=abc' but got '${refanged}'`);
}

const defangedBack = defangUrl('https://evil.com/login');
console.log(`Defanged 'https://evil.com/login' -> '${defangedBack}'`);
if (defangedBack !== 'hxxps://evil[.]com/login') {
  throw new Error(`Defanging failed: expected 'hxxps://evil[.]com/login' but got '${defangedBack}'`);
}

// Test 2: Homoglyphs
// Cyrillic 'а' (U+0430) in "paypal.com"
const cyrillicPayPal = 'p\u0430ypal.com';
const homoglyphResult = analyzeHomoglyphs(cyrillicPayPal);
console.log(`Homoglyph detection on '${cyrillicPayPal}':`, {
  hasHomoglyphs: homoglyphResult.hasHomoglyphs,
  spoofedBrand: homoglyphResult.spoofedBrand,
  riskLevel: homoglyphResult.riskLevel,
  detailsCount: homoglyphResult.details.length,
});
if (!homoglyphResult.hasHomoglyphs || homoglyphResult.spoofedBrand !== 'paypal') {
  throw new Error('Homoglyph detection failed to identify PayPal spoofing!');
}

// Test 3: Shannon Entropy
const highEntropyParam = 'aW5qZWN0X3BheWxvYWRfYzJfYmVhY29uXzEyODkzODQ3MjM5ODQ3Mjg5Mzc0';
const entropy = analyzeEntropy('/api/v1/session', `?data=${highEntropyParam}`, `http://evil.com/api/v1/session?data=${highEntropyParam}`);
console.log('Entropy calculation:', {
  pathEntropy: entropy.pathEntropy,
  queryEntropy: entropy.queryEntropy,
  isHighEntropy: entropy.isHighEntropy,
});
if (entropy.queryEntropy < 4.0) {
  throw new Error('Entropy calculation unexpectedly low for base64 encoded parameter');
}

// Test 4: Scoring Matrix
const norm = normalizeUrl('http://p\u0430ypal.xyz/account/login?token=abc');
const score = calculateThreatScore(
  norm,
  homoglyphResult,
  entropy,
  {
    virusTotal: { detected: true, positives: 14, total: 88 },
    urlhaus: { detected: false },
    urlscan: { detected: true, malicious: true },
    googleSafeBrowsing: { detected: true, threatTypes: ['SOCIAL_ENGINEERING'] },
    phishTank: { detected: true, verified: true },
  },
  {
    initialUrl: norm.canonicalUrl,
    finalUrl: norm.canonicalUrl,
    totalHops: 1,
    hops: [],
    evasionDetected: false,
    evasionReasons: [],
  },
  {
    title: 'PayPal Login Verify',
    metaTags: {},
    forms: [{ action: '/post', method: 'POST', hasPasswordInput: true, inputCount: 2, inputs: [] }],
    hasCredentialHarvester: true,
    scripts: [],
    consoleLogs: [],
    evalAttempts: 0,
    networkRequests: [],
    domSummary: { bodyLength: 500, linksCount: 2, imagesCount: 1, iframesCount: 0 },
  }
);

console.log('Scoring Matrix Result:', {
  score: score.overallScore,
  verdict: score.verdict,
  breakdownItems: score.breakdown.length,
});

if (score.verdict !== 'CRITICAL') {
  throw new Error(`Expected CRITICAL verdict for spoofed credential harvester, got ${score.verdict}`);
}

// Test 5: Detection Rules
const rules = generateDetectionRules('evil-domain.xyz', '/payload.exe', 'http://evil-domain.xyz/payload.exe', 'CRITICAL');
console.log('Generated Sigma Rule contains detection block:', rules.sigma.includes('selection_host:'));
console.log('Generated Suricata Rule contains sid:', rules.suricata.includes('sid:'));

console.log('\n>>> ALL ENGINE TESTS PASSED SUCCESSFULLY! <<<');
