import { ScanRequest, ScanReport } from './lib/types';
import {
  normalizeUrl,
  analyzeHomoglyphs,
  analyzeEntropy,
} from './lib/normalizer';
import { ingestThreatIntelligence } from './lib/threatIntel';
import { trackRedirectChain } from './lib/redirectTracker';
import { executeDomSandbox } from './lib/domSandbox';
import { calculateThreatScore } from './lib/scoringMatrix';
import { generateDetectionRules } from './lib/ruleExporter';
import { scanCache } from './lib/cache';

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Support GET /api/scan?id=...
  if (req.method === 'GET') {
    const { id } = req.query || {};
    if (!id) {
      return res.status(400).json({ error: 'Missing id query parameter' });
    }
    const report = scanCache.get(String(id));
    if (!report) {
      return res.status(404).json({ error: `Scan report '${id}' not found` });
    }
    return res.status(200).json(report);
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const body = req.body as ScanRequest;
  if (!body || !body.url) {
    return res.status(400).json({ error: 'Missing required field: url' });
  }

  const scanId = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  const timestamp = new Date().toISOString();

  try {
    // 1. URL Normalization & Defanging
    const norm = normalizeUrl(body.url);

    // 2. Homoglyph & Unicode Punycode Analysis
    const homoglyphs = analyzeHomoglyphs(norm.hostname);

    // 3. Shannon Entropy Calculation
    const entropy = analyzeEntropy(norm.pathname, norm.query, norm.canonicalUrl);

    // 4. Multi-Source Threat Intelligence
    const threatIntel = await ingestThreatIntelligence(norm, {
      virusTotalApiKey: body.options?.apiKeys?.virusTotal,
      urlscanApiKey: body.options?.apiKeys?.urlscan,
      googleSafeBrowsingApiKey: body.options?.apiKeys?.googleSafeBrowsing,
    });

    // 5. HTTP Redirect Chain Traversal
    const redirectChain = await trackRedirectChain(
      norm.canonicalUrl,
      8,
      body.options?.userAgent
    );

    // 6. Headless DOM Sandbox & Form Parsing
    const domSandbox = await executeDomSandbox(redirectChain.finalUrl || norm.canonicalUrl);

    // 7. Threat Scoring Matrix
    const scoring = calculateThreatScore(
      norm,
      homoglyphs,
      entropy,
      threatIntel,
      redirectChain,
      domSandbox
    );

    // 8. Detection Rules Exporter
    const rules = generateDetectionRules(
      norm.hostname,
      norm.pathname,
      norm.canonicalUrl,
      scoring.verdict
    );

    const report: ScanReport = {
      id: scanId,
      timestamp,
      inputUrl: body.url,
      status: 'completed',
      normalization: norm,
      homoglyphs,
      entropy,
      threatIntel,
      redirectChain,
      domSandbox,
      scoring,
      rules,
    };

    scanCache.set(scanId, report);
    return res.status(200).json(report);
  } catch (error: any) {
    console.error(`[Scan Error] Failed to scan ${body.url}:`, error);
    return res.status(500).json({
      id: scanId,
      status: 'failed',
      error: error.message || 'Internal sandbox analysis error',
    });
  }
}
