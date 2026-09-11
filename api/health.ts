import { scanCache } from './lib/cache';

export default function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

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
}
