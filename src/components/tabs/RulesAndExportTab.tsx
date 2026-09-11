import React, { useState } from 'react';
import { Copy, Check, FileDown, Shield, FileCode } from 'lucide-react';
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
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-sm">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">
            SIEM & IDS Detection Signatures
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Export ready-to-deploy detection rules for Splunk, Microsoft Sentinel, Suricata, and Chronicle.
          </p>
        </div>

        <button
          onClick={handleDownloadMarkdown}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs cursor-pointer transition-all shadow-sm shrink-0"
        >
          <FileDown className="w-4 h-4" />
          <span>Download Report (.md)</span>
        </button>
      </div>

      {/* Sigma Rule Box */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <FileCode className="w-4 h-4 text-purple-400" />
            <span>Sigma Detection Rule (YAML) — Web Proxy & DNS</span>
          </div>
          <button
            onClick={() => copyRule(rules.sigma, 'sigma')}
            className="flex items-center gap-1.5 text-xs text-slate-300 hover:text-white cursor-pointer px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-750 border border-slate-700/80 transition-colors"
          >
            {copiedType === 'sigma' ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5 text-slate-400" />
            )}
            <span>{copiedType === 'sigma' ? 'Copied' : 'Copy Rule'}</span>
          </button>
        </div>
        <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-slate-300 font-mono text-xs overflow-x-auto leading-relaxed">
          {rules.sigma}
        </pre>
      </div>

      {/* Suricata IDS Box */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span>Suricata IDS Network Rules (DNS, TLS SNI, HTTP)</span>
          </div>
          <button
            onClick={() => copyRule(rules.suricata, 'suricata')}
            className="flex items-center gap-1.5 text-xs text-slate-300 hover:text-white cursor-pointer px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-750 border border-slate-700/80 transition-colors"
          >
            {copiedType === 'suricata' ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5 text-slate-400" />
            )}
            <span>{copiedType === 'suricata' ? 'Copied' : 'Copy Rules'}</span>
          </button>
        </div>
        <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-slate-300 font-mono text-xs overflow-x-auto leading-relaxed">
          {rules.suricata}
        </pre>
      </div>

      {/* YARA-L & Snort Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* YARA-L */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80">
            <span className="text-xs font-semibold text-slate-200">YARA-L (Chronicle SIEM)</span>
            <button
              onClick={() => copyRule(rules.yaraL, 'yaral')}
              className="text-xs text-slate-400 hover:text-white cursor-pointer px-2 py-0.5 rounded hover:bg-slate-800"
            >
              {copiedType === 'yaral' ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto max-h-48">
            {rules.yaraL}
          </pre>
        </div>

        {/* Snort */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80">
            <span className="text-xs font-semibold text-slate-200">Snort Packet Filter</span>
            <button
              onClick={() => copyRule(rules.snort, 'snort')}
              className="text-xs text-slate-400 hover:text-white cursor-pointer px-2 py-0.5 rounded hover:bg-slate-800"
            >
              {copiedType === 'snort' ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto max-h-48">
            {rules.snort}
          </pre>
        </div>
      </div>
    </div>
  );
};
