import React from 'react';
import { Shield, Sliders, Database, Cpu, Sparkles } from 'lucide-react';

interface HeaderProps {
  onOpenSettings: () => void;
  cachedScansCount: number;
}

export const Header: React.FC<HeaderProps> = ({ onOpenSettings, cachedScansCount }) => {
  return (
    <header className="border-b border-slate-800/80 bg-[#0a0f1d]/90 backdrop-blur-md px-6 py-3.5 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/25 text-sky-400">
            <Shield className="w-5 h-5 text-sky-400" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-base tracking-tight text-white">
                Spider<span className="text-sky-400">LinkGuard</span>
              </span>
              <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-slate-800/90 text-slate-300 border border-slate-700/60">
                Security Sandbox
              </span>
            </div>
            <p className="text-xs text-slate-400 font-normal">
              Autonomous URL malware, phishing & redirect inspection
            </p>
          </div>
        </div>

        {/* Status Indicators & Actions */}
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-300">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-slate-400">ML Engine:</span>
            <span className="text-slate-200 font-medium">Active (Kaggle Model)</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Sandbox:</span>
            <span className="text-slate-200 font-medium">Isolated</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-300">
            <Database className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Scans:</span>
            <span className="text-slate-200 font-medium">{cachedScansCount}</span>
          </div>

          <button
            onClick={onOpenSettings}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/70 text-slate-200 hover:text-white transition-colors cursor-pointer font-medium"
            title="Configure Threat Intelligence API Keys"
          >
            <Sliders className="w-3.5 h-3.5 text-slate-400" />
            <span>API Keys</span>
          </button>
        </div>
      </div>
    </header>
  );
};
