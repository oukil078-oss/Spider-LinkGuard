import React, { useState } from 'react';
import { Copy, Check, FileDown, Shield, Terminal, FileCode } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface RulesAndExportTabProps {
  report: ScanReport;
}

export const RulesAndExportTab: React.FC<RulesAndExportTabProps> = ({ report }) => {
  const [copiedType, setCopiedType] = useState<string | null>(null);
  const { rules } = report;

  const copyRule = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const handleDownloadMarkdown = () => {
    window.open(`/api/scan/${report.id}/markdown`, '_blank');
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-sky-400 uppercase">
            <Terminal className="w-4 h-4" />
            <span>AUTO-GENERATED SIEM & IDS DETECTION ARTIFACTS</span>
          </div>
          <p className="text-xs font-sans text-slate-400 mt-1">
            Deploy these rules directly to your Splunk, Microsoft Sentinel, Suricata sensors, or Chronicle instances.
          </p>
        </div>

        <button
          onClick={handleDownloadMarkdown}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-mono font-bold text-xs cursor-pointer transition-all shadow-md shadow-sky-500/20"
        >
          <FileDown className="w-4 h-4" />
          <span>DOWNLOAD EXECUTIVE DOSSIER (.MD)</span>
        </button>
      </div>

      {/* Sigma Rule Box */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200 uppercase">
            <FileCode className="w-4 h-4 text-purple-400" />
            <span>SIGMA DETECTION RULE (YAML) — WEB PROXY / LOGS</span>
          </div>
          <button
            onClick={() => copyRule(rules.sigma, 'sigma')}
            className="flex items-center gap-1 text-xs font-mono text-slate-400 hover:text-sky-400 cursor-pointer px-2.5 py-1 rounded bg-slate-900 border border-slate-800"
          >
            {copiedType === 'sigma' ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
            <span>{copiedType === 'sigma' ? 'COPIED TO CLIPBOARD' : 'COPY SIGMA'}</span>
          </button>
        </div>
        <pre className="bg-slate-950 p-4 rounded-lg border border-slate-850 text-slate-300 font-mono text-xs overflow-x-auto leading-relaxed">
          {rules.sigma}
        </pre>
      </div>

      {/* Suricata IDS Box */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200 uppercase">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span>SURICATA IDS NETWORK SIGNATURES (DNS / TLS SNI / HTTP)</span>
          </div>
          <button
            onClick={() => copyRule(rules.suricata, 'suricata')}
            className="flex items-center gap-1 text-xs font-mono text-slate-400 hover:text-sky-400 cursor-pointer px-2.5 py-1 rounded bg-slate-900 border border-slate-800"
          >
            {copiedType === 'suricata' ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
            <span>{copiedType === 'suricata' ? 'COPIED TO CLIPBOARD' : 'COPY SURICATA'}</span>
          </button>
        </div>
        <pre className="bg-slate-950 p-4 rounded-lg border border-slate-850 text-slate-300 font-mono text-xs overflow-x-auto leading-relaxed">
          {rules.suricata}
        </pre>
      </div>

      {/* YARA-L & Snort Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* YARA-L */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
            <span className="text-xs font-mono font-bold text-slate-300">YARA-L (CHRONICLE SIEM)</span>
            <button
              onClick={() => copyRule(rules.yaraL, 'yaral')}
              className="text-xs font-mono text-slate-400 hover:text-sky-400 cursor-pointer"
            >
              {copiedType === 'yaral' ? 'COPIED!' : 'COPY'}
            </button>
          </div>
          <pre className="bg-slate-950 p-3 rounded border border-slate-850 text-slate-300 font-mono text-xs overflow-x-auto max-h-48">
            {rules.yaraL}
          </pre>
        </div>

        {/* Snort */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
            <span className="text-xs font-mono font-bold text-slate-300">SNORT PACKET FILTER</span>
            <button
              onClick={() => copyRule(rules.snort, 'snort')}
              className="text-xs font-mono text-slate-400 hover:text-sky-400 cursor-pointer"
            >
              {copiedType === 'snort' ? 'COPIED!' : 'COPY'}
            </button>
          </div>
          <pre className="bg-slate-950 p-3 rounded border border-slate-850 text-slate-300 font-mono text-xs overflow-x-auto max-h-48">
            {rules.snort}
          </pre>
        </div>
      </div>
    </div>
  );
};
