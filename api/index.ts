import express, { Request, Response } from 'express';
import cors from 'cors';
import { ScanReport, ScanRequest } from './_lib/types';
import {
  normalizeUrl,
  analyzeHomoglyphs,
  analyzeEntropy,
  defangUrl,
  refangUrl,
} from './_lib/normalizer';
import { ingestThreatIntelligence } from './_lib/threatIntel';
import { trackRedirectChain } from './_lib/redirectTracker';
import { executeDomSandbox } from './_lib/domSandbox';
import { calculateThreatScore } from './_lib/scoringMatrix';
import { generateDetectionRules, generateMarkdownReport } from './_lib/ruleExporter';
import { scanCache } from './_lib/cache';

const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));

/**
 * Health check & Engine telemetry
 */
app.get(['/api/health', '/health'], (_req: Request, res: Response) => {
  return res.status(200).json({
    status: 'healthy',
    service: 'Spider-LinkGuard API Engine',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    companionTo: "Zak's Spider SecOps Workstation",
    cachedScansCount: scanCache.size(),
    engines: {
      urlNormalizer: 'operational',
      homoglyphDetector: 'operational',
      entropyCalculator: 'operational',
      threatIntelAggregator: 'operational',
      redirectTracer: 'operational',
      domSandbox: 'operational',
      scoringMatrix: 'operational',
      ruleExporter: 'operational',
    },
  });
});

/**
 * Get all cached scans
 */
app.get(['/api/scans', '/scans'], (_req: Request, res: Response) => {
  return res.status(200).json(scanCache.getAll());
});

/**
 * Defang URL utility
 */
app.post(['/api/defang', '/defang'], (req: Request, res: Response) => {
  const { url } = req.body || {};
  if (!url) {
    return res.status(400).json({ error: 'url parameter is required' });
  }
  return res.status(200).json({
    original: url,
    defanged: defangUrl(url),
  });
});

/**
 * Refang URL utility
 */
app.post(['/api/refang', '/refang'], (req: Request, res: Response) => {
  const { url } = req.body || {};
  if (!url) {
    return res.status(400).json({ error: 'url parameter is required' });
  }
  return res.status(200).json({
    original: url,
    refanged: refangUrl(url),
  });
});

/**
 * Download Markdown Threat Dossier
 */
app.get(['/api/scan/:id/markdown', '/scan/:id/markdown'], (req: Request, res: Response) => {
  const { id } = req.params;
  const report = scanCache.get(id);

  if (!report) {
    return res.status(404).json({ error: `Scan report '${id}' not found` });
  }

  const markdown = generateMarkdownReport(report);
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="spider-linkguard-${report.id}.md"`
  );
  return res.status(200).send(markdown);
});

/**
 * Get specific scan report by ID
 */
app.get(['/api/scan/:id', '/scan/:id'], (req: Request, res: Response) => {
  const { id } = req.params;
  const report = scanCache.get(id);

  if (!report) {
    return res.status(404).json({ error: `Scan report '${id}' not found` });
  }

  return res.status(200).json(report);
});

/**
 * Main Execution Endpoint: /api/scan
 */
app.post(['/api/scan', '/scan'], async (req: Request, res: Response) => {
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
});

export default app;
