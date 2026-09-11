import React, { useState, useEffect } from 'react';
import { X, Key, Check, Save } from 'lucide-react';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (keys: { virusTotal?: string; urlscan?: string; googleSafeBrowsing?: string }) => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose, onSave }) => {
  const [vtKey, setVtKey] = useState('');
  const [urlscanKey, setUrlscanKey] = useState('');
  const [gsbKey, setGsbKey] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const savedVt = localStorage.getItem('spider_vt_key') || '';
    const savedUrlscan = localStorage.getItem('spider_urlscan_key') || '';
    const savedGsb = localStorage.getItem('spider_gsb_key') || '';
    setVtKey(savedVt);
    setUrlscanKey(savedUrlscan);
    setGsbKey(savedGsb);
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    localStorage.setItem('spider_vt_key', vtKey.trim());
    localStorage.setItem('spider_urlscan_key', urlscanKey.trim());
    localStorage.setItem('spider_gsb_key', gsbKey.trim());

    onSave({
      virusTotal: vtKey.trim() || undefined,
      urlscan: urlscanKey.trim() || undefined,
      googleSafeBrowsing: gsbKey.trim() || undefined,
    });

    setSaved(true);
    setTimeout(() => {
      setSaved(false);
      onClose();
    }, 1000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
      <div className="bg-[#0f1422] border border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl p-6 relative">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <Key className="w-5 h-5 text-sky-400" />
            <h3 className="font-semibold text-base text-slate-100">
              Threat Intelligence API Keys
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 cursor-pointer transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-slate-400 mb-5 leading-relaxed">
          Provide your own API keys for VirusTotal, urlscan.io, and Google Safe Browsing.
          If keys are omitted, the scanner uses our built-in machine learning classifier and public threat feeds.
        </p>

        <form onSubmit={handleSave} className="space-y-4 text-xs">
          <div>
            <label className="text-slate-300 block mb-1.5 font-medium">
              VirusTotal API Key (v3)
            </label>
            <input
              type="password"
              value={vtKey}
              onChange={(e) => setVtKey(e.target.value)}
              placeholder="e.g. 64-character hexadecimal key"
              className="w-full bg-slate-950 border border-slate-750 focus:border-sky-500 rounded-xl p-3 text-slate-200 focus:outline-none placeholder-slate-600 font-mono text-xs"
            />
          </div>

          <div>
            <label className="text-slate-300 block mb-1.5 font-medium">
              urlscan.io API Key
            </label>
            <input
              type="password"
              value={urlscanKey}
              onChange={(e) => setUrlscanKey(e.target.value)}
              placeholder="e.g. UUID API token"
              className="w-full bg-slate-950 border border-slate-750 focus:border-sky-500 rounded-xl p-3 text-slate-200 focus:outline-none placeholder-slate-600 font-mono text-xs"
            />
          </div>

          <div>
            <label className="text-slate-300 block mb-1.5 font-medium">
              Google Safe Browsing Key
            </label>
            <input
              type="password"
              value={gsbKey}
              onChange={(e) => setGsbKey(e.target.value)}
              placeholder="e.g. Google Cloud API key"
              className="w-full bg-slate-950 border border-slate-750 focus:border-sky-500 rounded-xl p-3 text-slate-200 focus:outline-none placeholder-slate-600 font-mono text-xs"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800/80">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-300 text-xs transition-colors cursor-pointer font-medium"
            >
              Cancel
            </button>

            <button
              type="submit"
              className="px-5 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-sm"
            >
              {saved ? (
                <>
                  <Check className="w-3.5 h-3.5 text-slate-950" />
                  <span>Saved</span>
                </>
              ) : (
                <>
                  <Save className="w-3.5 h-3.5" />
                  <span>Save Keys</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
