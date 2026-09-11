import { RedirectChain, RedirectHop } from './types';

const DEFAULT_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

/**
 * Traverses HTTP redirect chain step-by-step
 */
export async function trackRedirectChain(
  initialUrl: string,
  maxHops: number = 8,
  customUserAgent?: string
): Promise<RedirectChain> {
  const hops: RedirectHop[] = [];
  const evasionReasons: string[] = [];
  let currentUrl = initialUrl;
  let totalHops = 0;

  const userAgent = customUserAgent || DEFAULT_USER_AGENT;

  while (totalHops < maxHops) {
    const startTime = Date.now();
    let res: Response | null = null;
    let statusCode = 0;
    let statusText = '';
    const headersMap: Record<string, string> = {};
    const cookiesSet: string[] = [];
    let contentType = '';
    let nextUrl: string | null = null;
    let isMetaRefresh = false;
    let isJsRedirect = false;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);

      res = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        },
        signal: controller.signal,
      });

      clearTimeout(timeout);

      statusCode = res.status;
      statusText = res.statusText || `${res.status}`;
      contentType = res.headers.get('content-type') || 'unknown';

      res.headers.forEach((val, key) => {
        headersMap[key.toLowerCase()] = val;
        if (key.toLowerCase() === 'set-cookie') {
          cookiesSet.push(val.split(';')[0]);
        }
      });

      const location = res.headers.get('location');
      if (location && [301, 302, 303, 307, 308].includes(statusCode)) {
        try {
          nextUrl = new URL(location, currentUrl).href;
        } catch {
          nextUrl = location;
        }
      }

      if (!nextUrl && statusCode === 200 && contentType.includes('html')) {
        const text = await res.text();

        const metaMatch = text.match(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*content=["']?[0-9]*\s*;\s*url=([^"'>\s]+)["']?/i);
        if (metaMatch && metaMatch[1]) {
          isMetaRefresh = true;
          try {
            nextUrl = new URL(metaMatch[1], currentUrl).href;
          } catch {
            nextUrl = metaMatch[1];
          }
        }

        const jsMatch = text.match(/(?:window\.location(?:\.href)?|location\.replace)\s*=\s*["']([^"']+)["']/i);
        if (jsMatch && jsMatch[1] && !nextUrl) {
          isJsRedirect = true;
          try {
            nextUrl = new URL(jsMatch[1], currentUrl).href;
          } catch {
            nextUrl = jsMatch[1];
          }
        }
      }
    } catch (err: any) {
      statusCode = 504;
      statusText = err?.name === 'AbortError' ? 'Gateway Timeout' : 'Connection Failed';
      contentType = 'error';
    }

    const latencyMs = Date.now() - startTime;

    hops.push({
      hopIndex: totalHops,
      url: currentUrl,
      statusCode,
      statusText,
      latencyMs,
      headers: headersMap,
      cookiesSet,
      contentType,
      isMetaRefresh,
      isJsRedirect,
    });

    totalHops++;

    if (nextUrl) {
      const lowerNext = nextUrl.toLowerCase();
      if (lowerNext.includes('/mobile/') || lowerNext.includes('m.') || lowerNext.includes('platform=mobile')) {
        evasionReasons.push('Mobile-specific redirection detected (possible evasion targeting mobile devices).');
      }

      const currentDomain = new URL(currentUrl).hostname;
      const nextDomain = new URL(nextUrl).hostname;
      if (currentDomain !== nextDomain) {
        if (totalHops >= 2) {
          evasionReasons.push(`Multi-tier cross-domain hopping: ${currentDomain} -> ${nextDomain}`);
        }
      }

      currentUrl = nextUrl;
    } else {
      break;
    }
  }

  for (const hop of hops) {
    if (hop.headers['cf-mitigated'] || hop.headers['x-waf-event']) {
      evasionReasons.push('WAF or bot-mitigation challenge header detected.');
    }
    if (hop.statusCode === 403 || hop.statusCode === 401) {
      evasionReasons.push(`Access denied status ${hop.statusCode} (possible User-Agent or Geo-fencing block).`);
    }
  }

  if (totalHops > 4) {
    evasionReasons.push(`Deep redirection chain (${totalHops} hops) typically observed in spam, shorteners and bulletproof hosting.`);
  }

  return {
    initialUrl,
    finalUrl: hops[hops.length - 1]?.url || initialUrl,
    totalHops,
    hops,
    evasionDetected: evasionReasons.length > 0,
    evasionReasons: Array.from(new Set(evasionReasons)),
  };
}
