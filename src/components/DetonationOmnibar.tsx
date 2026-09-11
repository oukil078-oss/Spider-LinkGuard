import React, { useState } from 'react';
import { Search, Shield, Zap, RefreshCw, Copy, Check, Sparkles } from 'lucide-react';

interface DetonationOmnibarProps {
  onScan: (url: string, userAgent?: string) => void;
  isScanning: boolean;
}

const PRESETS = [
  {
    label: '🎣 Kaggle Phish',
    category: 'Phishing',
    url: 'http://paypal-verification-account-sec.top/login.php',
    description: 'Kaggle dataset credential harvester: spoofed brand + action keyword on suspicious TLD',
  },
  {
    label: '☣️ Kaggle Dropper',
    category: 'Malware',
    url: 'http://192.168.1.5:8080/gate/bot_payload.exe',
    description: 'Kaggle dataset malware dropper: direct IP addressing with port 8080 and .exe payload',
  },
  {
    label: '🏴‍☠️ Kaggle Webshell',
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
    label: '🛡️ Benign Clean',
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
    <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-2xl relative overflow-hidden">
      {/* Background ambient gradient glow */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-sky-500/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

      <div className="flex flex-col gap-4">
        {/* Title & Description */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-sky-400" />
            <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
              TARGET URL DETONATION OMNIBAR
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>UA Profile:</span>
            <select
              value={selectedUa}
              onChange={(e) => setSelectedUa(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-0.5 text-slate-200 text-xs focus:outline-none focus:border-sky-500"
            >
              <option value="desktop">Desktop Chrome 130</option>
              <option value="mobile">Mobile iPhone Safari</option>
              <option value="bot">Googlebot Crawler</option>
            </select>
          </div>
        </div>

        {/* Input Bar Form */}
        <form onSubmit={handleSubmit} className="flex flex-col md:flex-row items-center gap-2.5">
          <div className="relative flex-1 w-full">
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              placeholder="Paste raw URL or defanged IOC (e.g. hxxps://evil[.]com/login?token=abc)"
              className="w-full bg-[#070b13] border border-slate-750 focus:border-sky-500 rounded-lg px-4 py-3 text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none transition-all pr-24 shadow-inner"
              disabled={isScanning}
            />
            {inputUrl && (
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                <button
                  type="button"
                  onClick={copyToClipboard}
                  className="p-1.5 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
                  title="Copy to clipboard"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => setInputUrl('')}
                  className="px-2 py-1 text-xs font-mono text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
                >
                  CLEAR
                </button>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={!inputUrl.trim() || isScanning}
            className={`w-full md:w-auto px-6 py-3 rounded-lg font-mono font-bold text-sm tracking-wider flex items-center justify-center gap-2 cursor-pointer transition-all shadow-lg ${
              isScanning
                ? 'bg-sky-950 text-sky-400 border border-sky-800/80 cursor-wait'
                : inputUrl.trim()
                ? 'bg-sky-500 hover:bg-sky-400 text-slate-950 border border-sky-400 font-semibold shadow-sky-500/20'
                : 'bg-slate-800 text-slate-500 border border-slate-750 cursor-not-allowed'
            }`}
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-sky-400" />
                <span>DETONATING...</span>
              </>
            ) : (
              <>
                <Zap className="w-4 h-4" />
                <span>DETONATE & SCAN</span>
              </>
            )}
          </button>
        </form>

        {/* Action Strips: Defang/Refang toggles & Presets */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-slate-850">
          {/* Defang / Refang quick buttons */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-500">FORMAT:</span>
            <button
              type="button"
              onClick={handleDefang}
              className="px-2.5 py-1 text-xs font-mono text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded hover:border-slate-700 transition-colors"
              title="Convert to safe defanged format (hxxp:// and [.])"
            >
              DEFANG [.]
            </button>
            <button
              type="button"
              onClick={handleRefang}
              className="px-2.5 py-1 text-xs font-mono text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded hover:border-slate-700 transition-colors"
              title="Convert back to active URL"
            >
              REFANG
            </button>
          </div>

          {/* Preset Attack Vectors */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs font-mono text-slate-500 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-amber-400" />
              SAMPLES:
            </span>
            {PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                onClick={() => setInputUrl(p.url)}
                className="px-2.5 py-0.5 text-xs font-mono text-slate-300 hover:text-sky-300 bg-slate-900/80 hover:bg-slate-850 border border-slate-800 hover:border-sky-700 rounded transition-all cursor-pointer"
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
