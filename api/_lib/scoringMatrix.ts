import {
  UrlNormalization,
  HomoglyphAnalysis,
  EntropyAnalysis,
  ThreatIntelligence,
  RedirectChain,
  DomSandboxResult,
  ThreatScoreBreakdown,
  ScanVerdict,
} from './types';

export interface ScoringResult {
  overallScore: number;
  verdict: ScanVerdict;
  verdictReason: string;
  breakdown: ThreatScoreBreakdown[];
}

export function calculateThreatScore(
  norm: UrlNormalization,
  homoglyphs: HomoglyphAnalysis,
  entropy: EntropyAnalysis,
  threatIntel: ThreatIntelligence,
  redirects: RedirectChain,
  dom: DomSandboxResult
): ScoringResult {
  const breakdown: ThreatScoreBreakdown[] = [];
  let totalScore = 0;

  // 1. Threat Feeds (VirusTotal, URLhaus, Safe Browsing, PhishTank)
  if (threatIntel.urlhaus.detected) {
    totalScore += 40;
    breakdown.push({
      category: 'Threat Feeds',
      score: 40,
      weight: 40,
      description: `URLhaus (Abuse.ch) confirmed active threat: ${threatIntel.urlhaus.threat || 'Malware Payload'}`,
      severity: 'critical',
    });
  }

  if (threatIntel.virusTotal.positives > 0) {
    const vtScore = Math.min(45, threatIntel.virusTotal.positives * 4);
    totalScore += vtScore;
    breakdown.push({
      category: 'VirusTotal Intelligence',
      score: vtScore,
      weight: 45,
      description: `${threatIntel.virusTotal.positives} security vendors flagged URL as malicious/suspicious.`,
      severity: threatIntel.virusTotal.positives >= 5 ? 'critical' : 'malicious',
    });
  }

  if (threatIntel.googleSafeBrowsing.detected) {
    totalScore += 35;
    breakdown.push({
      category: 'Google Safe Browsing',
      score: 35,
      weight: 35,
      description: `Flagged by Google Safe Browsing: ${threatIntel.googleSafeBrowsing.threatTypes.join(', ')}`,
      severity: 'malicious',
    });
  }

  if (threatIntel.phishTank.detected) {
    totalScore += 35;
    breakdown.push({
      category: 'PhishTank Feed',
      score: 35,
      weight: 35,
      description: 'Matches known active phishing intelligence signatures.',
      severity: 'malicious',
    });
  }

  // 2. Homoglyphs & Brand Impersonation
  if (homoglyphs.hasHomoglyphs) {
    if (homoglyphs.spoofedBrand) {
      totalScore += 50;
      breakdown.push({
        category: 'Brand Homograph Spoofing',
        score: 50,
        weight: 50,
        description: `Deliberate lookalike Cyrillic/Unicode characters spoofing '${homoglyphs.spoofedBrand.toUpperCase()}'.`,
        severity: 'critical',
      });
    } else {
      totalScore += 25;
      breakdown.push({
        category: 'Confusable Characters',
        score: 25,
        weight: 30,
        description: `${homoglyphs.details.length} non-standard Cyrillic or confusable characters detected.`,
        severity: 'suspicious',
      });
    }
  }

  // 3. Credential Harvester DOM Detection
  if (dom.hasCredentialHarvester) {
    const isMajorTrusted = ['google.com', 'microsoft.com', 'github.com', 'apple.com'].some((d) =>
      norm.hostname.endsWith(d)
    );
    if (!isMajorTrusted) {
      totalScore += 35;
      breakdown.push({
        category: 'Credential Harvester',
        score: 35,
        weight: 40,
        description: 'DOM inspection revealed <input type="password"> on an untrusted or suspicious domain.',
        severity: 'malicious',
      });
    }
  }

  // 4. Suspicious TLD & Raw IP Hostname
  if (norm.isSuspiciousTld) {
    totalScore += 15;
    breakdown.push({
      category: 'TLD Reputation',
      score: 15,
      weight: 15,
      description: `Host operates on high-abuse TLD .${norm.tld} commonly associated with disposable campaigns.`,
      severity: 'suspicious',
    });
  }

  if (norm.isIp) {
    totalScore += 20;
    breakdown.push({
      category: 'Direct IP Addressing',
      score: 20,
      weight: 20,
      description: `Target uses raw IP (${norm.hostname}) bypassing standard domain reputation checks.`,
      severity: 'suspicious',
    });
  }

  // 5. Entropy & Obfuscation
  if (entropy.isHighEntropy) {
    totalScore += 20;
    breakdown.push({
      category: 'Payload Entropy',
      score: 20,
      weight: 20,
      description: `High Shannon entropy in query/path parameters (${entropy.queryEntropy || entropy.pathEntropy}): potential token/C2 beacon.`,
      severity: 'suspicious',
    });
  }

  // 6. Redirect Evasion Tactics
  if (redirects.evasionDetected) {
    totalScore += 20;
    breakdown.push({
      category: 'Redirect Evasion',
      score: 20,
      weight: 25,
      description: `Evasion indicators detected: ${redirects.evasionReasons.join('; ')}`,
      severity: 'suspicious',
    });
  }

  const normalizedScore = Math.min(100, Math.max(0, totalScore));

  let verdict: ScanVerdict = 'BENIGN';
  let verdictReason = 'No indicators of compromise or malicious intent observed.';

  if (normalizedScore >= 85) {
    verdict = 'CRITICAL';
    verdictReason =
      'CRITICAL THREAT: Active weaponized link, confirmed brand impersonation, or verified malware drop.';
  } else if (normalizedScore >= 60) {
    verdict = 'MALICIOUS';
    verdictReason =
      'HIGH RISK: Flagged by multiple threat engines, credential harvesting forms, or deceptive patterns.';
  } else if (normalizedScore >= 25) {
    verdict = 'SUSPICIOUS';
    verdictReason =
      'ELEVATED RISK: Anomalous characteristics detected (high entropy, suspicious TLD, or evasive hops).';
  }

  if (breakdown.length === 0) {
    breakdown.push({
      category: 'Baseline Heuristics',
      score: 0,
      weight: 100,
      description: 'Domain and link structure match benign operational profile.',
      severity: 'clean',
    });
  }

  return {
    overallScore: normalizedScore,
    verdict,
    verdictReason,
    breakdown,
  };
}
