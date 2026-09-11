import React, { useState, useEffect } from 'react';
import { X, Key, Shield, Check, Save } from 'lucide-react';

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
      <div className="bg-[#0b101b] border border-slate-750 rounded-xl w-full max-w-lg shadow-2xl p-6 relative">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Key className="w-5 h-5 text-sky-400" />
            <h3 className="font-mono font-bold text-sm text-slate-100 uppercase tracking-wider">
              THREAT INTELLIGENCE API CREDENTIALS
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-800 cursor-pointer transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs font-sans text-slate-300 mb-5 leading-relaxed">
          Optionally provide your own threat intelligence API keys. If keys are omitted,
          Spider-LinkGuard gracefully utilizes public community endpoints (such as URLhaus Abuse.ch)
          and local high-fidelity heuristic simulation.
        </p>

        <form onSubmit={handleSave} className="space-y-4 font-mono text-xs">
          <div>
            <label className="text-slate-400 block mb-1 font-bold">
              VIRUSTOTAL API v3 KEY:
            </label>
            <input
              type="password"
              value={vtKey}
              onChange={(e) => setVtKey(e.target.value)}
              placeholder="e.g. 64-character hexadecimal VT API key"
              className="w-full bg-slate-950 border border-slate-800 focus:border-sky-500 rounded p-2.5 text-slate-200 focus:outline-none placeholder-slate-600"
            />
          </div>

          <div>
            <label className="text-slate-400 block mb-1 font-bold">
              URLSCAN.IO API KEY:
            </label>
            <input
              type="password"
              value={urlscanKey}
              onChange={(e) => setUrlscanKey(e.target.value)}
              placeholder="e.g. UUID urlscan.io API token"
              className="w-full bg-slate-950 border border-slate-800 focus:border-sky-500 rounded p-2.5 text-slate-200 focus:outline-none placeholder-slate-600"
            />
          </div>

          <div>
            <label className="text-slate-400 block mb-1 font-bold">
              GOOGLE SAFE BROWSING v4 KEY:
            </label>
            <input
              type="password"
              value={gsbKey}
              onChange={(e) => setGsbKey(e.target.value)}
              placeholder="e.g. Google Cloud Safe Browsing API key"
              className="w-full bg-slate-950 border border-slate-800 focus:border-sky-500 rounded p-2.5 text-slate-200 focus:outline-none placeholder-slate-600"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 font-mono text-xs border border-slate-800 transition-colors cursor-pointer"
            >
              CANCEL
            </button>

            <button
              type="submit"
              className="px-5 py-2 rounded bg-sky-500 hover:bg-sky-400 text-slate-950 font-mono font-bold text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-md shadow-sky-500/20"
            >
              {saved ? (
                <>
                  <Check className="w-3.5 h-3.5 text-slate-950" />
                  <span>SAVED!</span>
                </>
              ) : (
                <>
                  <Save className="w-3.5 h-3.5" />
                  <span>SAVE SETTINGS</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
