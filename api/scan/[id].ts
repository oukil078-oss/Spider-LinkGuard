import { scanCache } from '../lib/cache';

export default function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

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
