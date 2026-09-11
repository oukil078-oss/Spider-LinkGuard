import React from 'react';
import { ShieldAlert, Cpu, Database, Sliders, Activity, Terminal } from 'lucide-react';

interface HeaderProps {
  onOpenSettings: () => void;
  cachedScansCount: number;
}

export const Header: React.FC<HeaderProps> = ({ onOpenSettings, cachedScansCount }) => {
  return (
    <header className="border-b border-slate-800 bg-[#0b101b] px-6 py-3.5 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand & Subtitle */}
        <div className="flex items-center gap-3.5">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400">
            <ShieldAlert className="w-5 h-5 text-sky-400" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
          </div>

          <div>
            <div className="flex items-center gap-2.5">
              <span className="font-mono font-bold text-lg tracking-wider text-slate-100">
                SPIDER<span className="text-sky-400">-LINKGUARD</span>
              </span>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-sky-950/80 border border-sky-800/60 text-sky-300">
                <Terminal className="w-3 h-3" />
                ZAK'S SECOPS COMPANION
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans tracking-wide">
              Automated URL Malware, Phishing & Headless Detonation Sandbox
            </p>
          </div>
        </div>

        {/* System Telemetry & Capsules */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400">SANDBOX:</span>
            <span className="text-emerald-400 font-semibold">CHROMIUM ISOLATED</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
            <Activity className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-slate-400">FEEDS:</span>
            <span className="text-sky-300 font-semibold">5 ENGINES</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
            <Database className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-slate-400">CACHED:</span>
            <span className="text-purple-300 font-semibold">{cachedScansCount} DOSSIERS</span>
          </div>

          <button
            onClick={onOpenSettings}
            className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-slate-800 hover:bg-slate-750 border border-slate-700 text-xs font-mono text-slate-200 hover:text-white transition-colors cursor-pointer"
            title="Configure Threat Intelligence API Keys"
          >
            <Sliders className="w-3.5 h-3.5 text-slate-400" />
            <span>API KEYS</span>
          </button>
        </div>
      </div>
    </header>
  );
};
