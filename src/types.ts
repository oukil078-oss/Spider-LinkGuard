export interface ScanRequest {
  url: string;
  options?: {
    userAgent?: string;
    followRedirects?: boolean;
    timeoutMs?: number;
    apiKeys?: {
      virusTotal?: string;
      urlscan?: string;
      googleSafeBrowsing?: string;
    };
  };
}

export interface UrlNormalization {
  originalUrl: string;
  canonicalUrl: string;
  defangedUrl: string;
  scheme: string;
  hostname: string;
  port: string;
  pathname: string;
  query: string;
  hash: string;
  isIp: boolean;
  ipVersion?: 'v4' | 'v6';
  tld: string;
  sld: string;
  subdomains: string[];
  isSuspiciousTld: boolean;
}

export interface HomoglyphCharacter {
  char: string;
  index: number;
  unicode: string;
  latinEquivalent: string;
  description: string;
}

export interface HomoglyphAnalysis {
  hasHomoglyphs: boolean;
  punycode: string;
  isPunycodeEncoded: boolean;
  spoofedBrand?: string;
  riskLevel: 'clean' | 'suspicious' | 'critical';
  details: HomoglyphCharacter[];
  explanation: string;
}

export interface EntropyAnalysis {
  pathEntropy: number;
  queryEntropy: number;
  fullUrlEntropy: number;
  isHighEntropy: boolean;
  riskLevel: 'clean' | 'suspicious' | 'high';
  analysisNotes: string[];
}

export interface ThreatIntelligence {
  virusTotal: {
    detected: boolean;
    positives: number;
    total: number;
    scanDate?: string;
    permalink?: string;
    engineResults?: Record<string, { category: string; result: string }>;
  };
  urlhaus: {
    detected: boolean;
    status?: string;
    threat?: string;
    tags?: string[];
    reporter?: string;
    dateAdded?: string;
    urlhausReference?: string;
  };
  urlscan: {
    detected: boolean;
    malicious: boolean;
    score?: number;
    tags?: string[];
    country?: string;
    asn?: string;
    asnName?: string;
    screenshotUrl?: string;
    pageTitle?: string;
    ip?: string;
  };
  googleSafeBrowsing: {
    detected: boolean;
    threatTypes: string[];
  };
  phishTank: {
    detected: boolean;
    verified: boolean;
    phishingUrl?: string;
  };
}

export interface RedirectHop {
  hopIndex: number;
  url: string;
  statusCode: number;
  statusText: string;
  latencyMs: number;
  headers: Record<string, string>;
  cookiesSet: string[];
  contentType: string;
  isMetaRefresh?: boolean;
  isJsRedirect?: boolean;
}

export interface RedirectChain {
  initialUrl: string;
  finalUrl: string;
  totalHops: number;
  hops: RedirectHop[];
  evasionDetected: boolean;
  evasionReasons: string[];
}

export interface DomFormInput {
  name: string;
  type: string;
  placeholder?: string;
  required?: boolean;
}

export interface DomForm {
  action: string;
  method: string;
  hasPasswordInput: boolean;
  inputCount: number;
  inputs: DomFormInput[];
}

export interface DomScript {
  src: string;
  isExternal: boolean;
  isSuspicious: boolean;
  domain?: string;
}

export interface NetworkRequestEntry {
  url: string;
  method: string;
  status: number;
  type: string;
  size: number;
  external: boolean;
}

export interface DomSandboxResult {
  title: string;
  metaTags: Record<string, string>;
  forms: DomForm[];
  hasCredentialHarvester: boolean;
  scripts: DomScript[];
  consoleLogs: Array<{ level: string; text: string }>;
  evalAttempts: number;
  screenshotBase64?: string;
  networkRequests: NetworkRequestEntry[];
  domSummary: {
    bodyLength: number;
    linksCount: number;
    imagesCount: number;
    iframesCount: number;
  };
}

export interface ThreatScoreBreakdown {
  category: string;
  score: number;
  weight: number;
  description: string;
  severity: 'clean' | 'info' | 'suspicious' | 'malicious' | 'critical';
}

export type ScanVerdict = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL';

export interface DetectionRules {
  sigma: string;
  suricata: string;
  snort: string;
  yaraL: string;
}

export interface MlClassification {
  predictedCategory: 'benign' | 'phishing' | 'malware' | 'defacement';
  confidence: number;
  mlRiskScore: number;
  modelName: string;
  featuresTriggered: string[];
  classProbabilities: {
    benign: number;
    phishing: number;
    malware: number;
    defacement: number;
  };
}

export interface DatasetMatchResult {
  matched: boolean;
  source?: string;
  threatCategory?: 'malware' | 'phishing' | 'defacement' | 'suspicious';
  pattern?: string;
  confidence: number;
  description?: string;
}

export interface ScanReport {
  id: string;
  timestamp: string;
  inputUrl: string;
  status: 'running' | 'completed' | 'failed';
  error?: string;
  normalization: UrlNormalization;
  homoglyphs: HomoglyphAnalysis;
  entropy: EntropyAnalysis;
  threatIntel: ThreatIntelligence;
  redirectChain: RedirectChain;
  domSandbox: DomSandboxResult;
  mlClassification?: MlClassification;
  datasetIntel?: DatasetMatchResult;
  scoring: {
    overallScore: number;
    verdict: ScanVerdict;
    verdictReason: string;
    breakdown: ThreatScoreBreakdown[];
  };
  rules: DetectionRules;
}

export interface ScanHistorySummary {
  id: string;
  timestamp: string;
  inputUrl: string;
  hostname: string;
  verdict: ScanVerdict;
  overallScore: number;
  hasCredentialHarvester: boolean;
  totalHops: number;
}
