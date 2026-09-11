import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { ScanReport, ScanRequest } from './_lib/types.js';
import {
  normalizeUrl,
  analyzeHomoglyphs,
  analyzeEntropy,
  defangUrl,
  refangUrl,
} from './_lib/normalizer.js';
import { ingestThreatIntelligence } from './_lib/threatIntel.js';
import { trackRedirectChain } from './_lib/redirectTracker.js';
import { executeDomSandbox } from './_lib/domSandbox.js';
import { calculateThreatScore } from './_lib/scoringMatrix.js';
import { classifyUrlWithMl } from './_lib/mlClassifier.js';
import { lookupDatasetThreat } from './_lib/datasetIntel.js';
import { generateDetectionRules, generateMarkdownReport } from './_lib/ruleExporter.js';
import { scanCache } from './_lib/cache.js';

const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Middleware to normalize rewritten routes from Vercel: /api?_route=health -> /health
app.use((req: Request, _res: Response, next: NextFunction) => {
  const route = req.query._route;
  if (route && typeof route === 'string') {
    req.url = '/' + route.replace(/^\//, '');
  }
  next();
});

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
      mlClassifier: 'operational',
      datasetThreatIntel: 'operational',
      ruleExporter: 'operational',
    },
  });
});

/**
 * Root /api handler
 */
app.get(['/api', '/'], (_req: Request, res: Response) => {
  return res.status(200).json({
    service: 'Spider-LinkGuard API Engine',
    status: 'operational',
    endpoints: [
      'GET /api/health',
      'GET /api/scans',
      'POST /api/scan',
      'GET /api/scan/:id',
      'GET /api/scan/:id/markdown',
      'POST /api/defang',
      'POST /api/refang',
    ],
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
  const id = String(req.params.id);
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
  const id = String(req.params.id);
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

    // 7. Kaggle Lexical ML Classification & Dataset Intel Lookup
    const mlClassification = classifyUrlWithMl(body.url, norm);
    const datasetIntel = lookupDatasetThreat(body.url, norm);

    // 8. Threat Scoring Matrix
    const scoring = calculateThreatScore(
      norm,
      homoglyphs,
      entropy,
      threatIntel,
      redirectChain,
      domSandbox,
      mlClassification,
      datasetIntel
    );

    // 9. Detection Rules Exporter
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
      mlClassification,
      datasetIntel,
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
