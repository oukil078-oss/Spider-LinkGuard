import { defangUrl } from './lib/normalizer';

export default function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { url } = req.body || {};
  if (!url) {
    return res.status(400).json({ error: 'url parameter is required' });
  }

  return res.status(200).json({
    original: url,
    defanged: defangUrl(url),
  });
}
