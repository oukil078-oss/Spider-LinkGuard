import React, { useState } from 'react';
import { Search, Globe, Shield, RefreshCw, Copy, Check, Sparkles, ArrowRight, X } from 'lucide-react';

interface DetonationOmnibarProps {
  onScan: (url: string, userAgent?: string) => void;
  isScanning: boolean;
}

const PRESETS = [
  {
    label: '🎣 Phishing Sample',
    category: 'Phishing',
    url: 'http://paypal-verification-account-sec.top/login.php',
    description: 'Kaggle dataset credential harvester: spoofed brand + action keyword on suspicious TLD',
  },
  {
    label: '☣️ Malware Dropper',
    category: 'Malware',
    url: 'http://192.168.1.5:8080/gate/bot_payload.exe',
    description: 'Kaggle dataset malware dropper: direct IP addressing with port 8080 and .exe payload',
  },
  {
    label: '🏴‍☠️ Webshell Pattern',
    category: 'Defacement',
    url: 'http://vulnerable-cms.org/wp-content/plugins/c99.php',
    description: 'Kaggle dataset defacement/backdoor: classic c99.php remote administration webshell',
  },
  {
    label: 'PayPаl Homoglyph',
    category: 'Homograph',
    url: 'http://p\u0430ypal.com/signin?claim=refund_592',
    description: 'Brand spoofing using Cyrillic lookalike "а" (U+0430)',
  },
  {
    label: '🛡️ Safe Domain',
    category: 'Clean',
    url: 'https://en.wikipedia.org/wiki/Computer_security',
    description: 'Verified benign reference URL matching clean operational profiles',
  },
];

export const DetonationOmnibar: React.FC<DetonationOmnibarProps> = ({ onScan, isScanning }) => {
  const [inputUrl, setInputUrl] = useState('');
  const [selectedUa, setSelectedUa] = useState<string>('desktop');
  const [copied, setCopied] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim() || isScanning) return;
    onScan(inputUrl.trim(), getUaString(selectedUa));
  };

  const getUaString = (type: string) => {
    switch (type) {
      case 'mobile':
        return 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';
      case 'bot':
        return 'Googlebot/2.1 (+http://www.google.com/bot.html)';
      default:
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
    }
  };

  const handleDefang = () => {
    let u = inputUrl.trim();
    u = u.replace(/^http:\/\//i, 'hxxp://');
    u = u.replace(/^https:\/\//i, 'hxxps://');
    u = u.replace(/\./g, '[.]');
    setInputUrl(u);
  };

  const handleRefang = () => {
    let u = inputUrl.trim();
    u = u.replace(/^hxxp:\/\//i, 'http://');
    u = u.replace(/^hxxps:\/\//i, 'https://');
    u = u.replace(/\[\.\]/g, '.');
    u = u.replace(/\(\.\)/g, '.');
    setInputUrl(u);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(inputUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-[#0f1422] border border-slate-800/90 rounded-2xl p-6 shadow-xl">
      <div className="flex flex-col gap-4">
        {/* Header and User-Agent */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold text-slate-100 tracking-tight">
              Inspect a Link or Domain
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Paste a URL to scan for phishing lures, malware droppers, webshells, and redirect evasion.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Browser Profile:</span>
            <select
              value={selectedUa}
              onChange={(e) => setSelectedUa(e.target.value)}
              className="bg-slate-900 border border-slate-750 text-slate-200 rounded-lg px-2.5 py-1 text-xs focus:outline-none focus:border-sky-500 cursor-pointer"
            >
              <option value="desktop">Desktop (Chrome 130)</option>
              <option value="mobile">Mobile (iPhone Safari)</option>
              <option value="bot">Crawler (Googlebot)</option>
            </select>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-center gap-2.5">
          <div className="relative flex-1 w-full">
            <div className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400">
              <Search className="w-4 h-4" />
            </div>

            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              placeholder="Enter URL to inspect (e.g., https://example.com or hxxps://evil[.]com)"
              className="w-full bg-[#080d18] border border-slate-750 focus:border-sky-500 rounded-xl pl-10 pr-24 py-3 text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none transition-all shadow-sm"
              disabled={isScanning}
            />

            {inputUrl && (
              <div className="absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-1">
                <button
                  type="button"
                  onClick={copyToClipboard}
                  className="p-1 text-slate-400 hover:text-slate-200 rounded-md hover:bg-slate-800 transition-colors"
                  title="Copy"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => setInputUrl('')}
                  className="p-1 text-slate-400 hover:text-slate-200 rounded-md hover:bg-slate-800 transition-colors"
                  title="Clear input"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={!inputUrl.trim() || isScanning}
            className={`w-full sm:w-auto px-6 py-3 rounded-xl font-medium text-sm flex items-center justify-center gap-2 cursor-pointer transition-all shadow-md shrink-0 ${
              isScanning
                ? 'bg-sky-950/80 text-sky-400 border border-sky-800/60 cursor-wait'
                : inputUrl.trim()
                ? 'bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold shadow-sky-500/10'
                : 'bg-slate-800 text-slate-500 border border-slate-750 cursor-not-allowed'
            }`}
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-sky-400" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <span>Scan URL</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Quick actions: Defang / Refang + Test Samples */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 text-xs border-t border-slate-800/80">
          <div className="flex items-center gap-2">
            <span className="text-slate-500 font-normal">Format:</span>
            <button
              type="button"
              onClick={handleDefang}
              className="px-2 py-0.5 text-xs text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-750 border border-slate-700/60 rounded-md transition-colors"
              title="Convert to safe defanged format (hxxps:// and [.])"
            >
              Defang [.]
            </button>
            <button
              type="button"
              onClick={handleRefang}
              className="px-2 py-0.5 text-xs text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-750 border border-slate-700/60 rounded-md transition-colors"
              title="Convert back to live URL"
            >
              Refang
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-slate-500 font-normal flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-amber-400" />
              Test samples:
            </span>
            {PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                onClick={() => setInputUrl(p.url)}
                className="px-2.5 py-1 text-xs text-slate-300 hover:text-sky-300 bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 rounded-lg transition-all cursor-pointer"
                title={p.description}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
