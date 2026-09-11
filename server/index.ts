import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { ScanReport, ScanRequest } from './types/scanner.ts';
import {
  normalizeUrl,
  analyzeHomoglyphs,
  analyzeEntropy,
  defangUrl,
  refangUrl,
} from './engines/normalizer.ts';
import { ingestThreatIntelligence } from './engines/threatIntel.ts';
import { trackRedirectChain } from './engines/redirectTracker.ts';
import { executeDomSandbox } from './engines/domSandbox.ts';
import { calculateThreatScore } from './engines/scoringMatrix.ts';
import { classifyUrlWithMl } from './engines/mlClassifier.ts';
import { lookupDatasetThreat } from './engines/datasetIntel.ts';
import { generateDetectionRules, generateMarkdownReport } from './engines/ruleExporter.ts';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// In-memory Scan Cache (stores up to 100 reports)
const scanReports = new Map<string, ScanReport>();

/**
 * Health check & Engine telemetry
 */
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'Spider-LinkGuard API Engine',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    companionTo: "Zak's Spider SecOps Workstation",
    cachedScansCount: scanReports.size,
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
 * Quick Defang API
 */
app.post('/api/defang', (req: Request, res: Response) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  const defanged = defangUrl(url);
  return res.json({ original: url, defanged });
});

/**
 * Quick Refang API
 */
app.post('/api/refang', (req: Request, res: Response) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  const refanged = refangUrl(url);
  return res.json({ original: url, refanged });
});

/**
 * Get all cached scans
 */
app.get('/api/scans', (_req: Request, res: Response) => {
  const list = Array.from(scanReports.values())
    .map((report) => ({
      id: report.id,
      timestamp: report.timestamp,
      inputUrl: report.inputUrl,
      hostname: report.normalization.hostname,
      verdict: report.scoring.verdict,
      overallScore: report.scoring.overallScore,
      hasCredentialHarvester: report.domSandbox.hasCredentialHarvester,
      totalHops: report.redirectChain.totalHops,
    }))
    .reverse();

  res.json(list);
});

/**
 * Get specific scan report
 */
app.get('/api/scan/:id', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const report = scanReports.get(id);
  if (!report) {
    return res.status(404).json({ error: `Scan report '${id}' not found` });
  }
  res.json(report);
});

/**
 * Export scan report as Markdown
 */
app.get('/api/scan/:id/markdown', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const report = scanReports.get(id);
  if (!report) {
    return res.status(404).json({ error: `Scan report '${id}' not found` });
  }
  const markdown = generateMarkdownReport(report);
  res.setHeader('Content-Type', 'text/markdown');
  res.setHeader('Content-Disposition', `attachment; filename="Spider-LinkGuard-${id}.md"`);
  res.send(markdown);
});

/**
 * Main URL Detonation & Analysis Engine
 * Zak's Spider pivot endpoint
 */
app.post('/api/scan', async (req: Request, res: Response) => {
  const body: ScanRequest = req.body;
  if (!body.url || typeof body.url !== 'string') {
    return res.status(400).json({ error: 'Valid URL is required' });
  }

  const scanId = `SLG-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

  try {
    console.log(`[Scan ${scanId}] Step 1: Normalizing ${body.url}`);
    const norm = normalizeUrl(body.url);
    const homoglyphs = analyzeHomoglyphs(norm.hostname);
    const entropy = analyzeEntropy(norm.pathname, norm.query, norm.canonicalUrl);

    console.log(`[Scan ${scanId}] Step 2: Ingesting Threat Intel`);
    const threatIntel = await ingestThreatIntelligence(norm, {
      virusTotalApiKey: body.options?.apiKeys?.virusTotal || process.env.VIRUSTOTAL_API_KEY,
      urlscanApiKey: body.options?.apiKeys?.urlscan || process.env.URLSCAN_API_KEY,
      googleSafeBrowsingApiKey:
        body.options?.apiKeys?.googleSafeBrowsing || process.env.GOOGLE_SAFE_BROWSING_API_KEY,
    });

    console.log(`[Scan ${scanId}] Step 3: Traversing Redirects`);
    const redirectChain = await trackRedirectChain(norm.canonicalUrl, 8, body.options?.userAgent);

    console.log(`[Scan ${scanId}] Step 4: Executing DOM Sandbox`);
    const finalDestinationUrl = redirectChain.finalUrl || norm.canonicalUrl;
    const domSandbox = await executeDomSandbox(finalDestinationUrl);

    console.log(`[Scan ${scanId}] Step 5: Kaggle Lexical ML & Dataset Threat Lookup`);
    const mlClassification = classifyUrlWithMl(body.url, norm);
    const datasetIntel = lookupDatasetThreat(body.url, norm);

    console.log(`[Scan ${scanId}] Step 6: Scoring Matrix`);
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

    console.log(`[Scan ${scanId}] Step 7: Generating Detection Rules`);
    const rules = generateDetectionRules(
      norm.hostname,
      norm.pathname,
      norm.canonicalUrl,
      scoring.verdict
    );

    const report: ScanReport = {
      id: scanId,
      timestamp: new Date().toISOString(),
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

    // Store in cache (limit 100)
    if (scanReports.size > 100) {
      const oldestKey = scanReports.keys().next().value;
      if (oldestKey) scanReports.delete(oldestKey);
    }
    scanReports.set(scanId, report);

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

if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`[Spider-LinkGuard API] Listening on http://localhost:${PORT}`);
    console.log(`[Spider-LinkGuard API] Ready to receive scan pivots from Zak's Spider`);
  });
}

export default app;
