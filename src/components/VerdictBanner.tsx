import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  FileDown,
  Copy,
  Check,
  Printer,
  FileCode,
  ExternalLink,
} from 'lucide-react';
import { ScanReport, ScanVerdict } from '../types.ts';

interface VerdictBannerProps {
  report: ScanReport;
}

export const VerdictBanner: React.FC<VerdictBannerProps> = ({ report }) => {
  const [copiedAction, setCopiedAction] = useState<string | null>(null);

  const { overallScore, verdict, verdictReason } = report.scoring;

  const getVerdictConfig = (v: ScanVerdict) => {
    switch (v) {
      case 'CRITICAL':
        return {
          icon: <ShieldAlert className="w-6 h-6 text-rose-400" />,
          label: 'Critical Risk',
          badgeClass: 'bg-rose-500/10 text-rose-400 border-rose-500/25',
          dotColor: 'bg-rose-500',
          scoreColor: 'text-rose-400',
          barColor: 'bg-rose-500',
          borderClass: 'border-rose-900/40 bg-[#160d15]/60',
        };
      case 'MALICIOUS':
        return {
          icon: <ShieldAlert className="w-6 h-6 text-red-400" />,
          label: 'Malicious',
          badgeClass: 'bg-red-500/10 text-red-400 border-red-500/25',
          dotColor: 'bg-red-500',
          scoreColor: 'text-red-400',
          barColor: 'bg-red-500',
          borderClass: 'border-red-900/40 bg-[#170e12]/60',
        };
      case 'SUSPICIOUS':
        return {
          icon: <AlertTriangle className="w-6 h-6 text-amber-400" />,
          label: 'Suspicious',
          badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/25',
          dotColor: 'bg-amber-500',
          scoreColor: 'text-amber-400',
          barColor: 'bg-amber-500',
          borderClass: 'border-amber-900/40 bg-[#17140e]/60',
        };
      default:
        return {
          icon: <ShieldCheck className="w-6 h-6 text-emerald-400" />,
          label: 'Clean & Safe',
          badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25',
          dotColor: 'bg-emerald-500',
          scoreColor: 'text-emerald-400',
          barColor: 'bg-emerald-500',
          borderClass: 'border-emerald-900/40 bg-[#0d1714]/60',
        };
    }
  };

  const config = getVerdictConfig(verdict);

  const copyText = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedAction(label);
    setTimeout(() => setCopiedAction(null), 2000);
  };

  const handleDownloadMarkdown = () => {
    window.open(`/api/scan/${report.id}/markdown`, '_blank');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className={`rounded-2xl border ${config.borderClass} p-6 shadow-xl transition-all`}>
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
        {/* Left Section: Verdict & Details */}
        <div className="flex items-start gap-4 flex-1 min-w-0">
          <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 shrink-0">
            {config.icon}
          </div>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5 mb-1.5">
              <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${config.badgeClass}`}>
                <span className={`w-2 h-2 rounded-full ${config.dotColor}`} />
                {config.label}
              </span>
              <span className="text-xs text-slate-400">
                Scan ID: <span className="font-mono text-slate-300">{report.id}</span>
              </span>
            </div>

            <p className="text-sm font-medium text-slate-200 max-w-2xl leading-relaxed">
              {verdictReason}
            </p>

            {/* Target URL chip */}
            <div className="flex flex-wrap items-center gap-2 mt-3 text-xs">
              <span className="text-slate-400 font-medium">Target:</span>
              <div className="flex items-center gap-1.5 max-w-full bg-slate-900/90 border border-slate-800/90 rounded-lg px-2.5 py-1 text-slate-300 font-mono text-xs overflow-hidden">
                <span className="truncate max-w-md sm:max-w-xl">{report.normalization.canonicalUrl}</span>
                <button
                  onClick={() => copyText(report.normalization.canonicalUrl, 'url')}
                  className="text-slate-400 hover:text-white p-0.5 rounded transition-colors shrink-0"
                  title="Copy URL"
                >
                  {copiedAction === 'url' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Center: Risk Score */}
        <div className="flex flex-col items-center justify-center min-w-[150px] bg-slate-900/90 border border-slate-800 rounded-xl p-4 shrink-0">
          <span className="text-xs font-medium text-slate-400 mb-1">
            Threat Score
          </span>
          <div className="flex items-baseline gap-1">
            <span className={`text-3xl font-bold font-mono ${config.scoreColor}`}>
              {overallScore}
            </span>
            <span className="text-xs text-slate-500 font-medium">/ 100</span>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full mt-2.5 overflow-hidden">
            <div
              className={`h-full ${config.barColor} transition-all duration-700`}
              style={{ width: `${Math.max(5, overallScore)}%` }}
            />
          </div>
        </div>

        {/* Right Section: Action Buttons */}
        <div className="flex flex-col sm:flex-row lg:flex-col gap-2 w-full lg:w-auto shrink-0">
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => copyText(report.normalization.defangedUrl, 'defanged')}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white transition-all cursor-pointer"
              title="Copy safe defanged URL"
            >
              {copiedAction === 'defanged' ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5 text-slate-400" />
              )}
              <span>{copiedAction === 'defanged' ? 'Copied' : 'Copy Defanged'}</span>
            </button>

            <button
              onClick={() => copyText(report.rules.sigma, 'sigma')}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white transition-all cursor-pointer"
              title="Copy Sigma rule"
            >
              {copiedAction === 'sigma' ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <FileCode className="w-3.5 h-3.5 text-slate-400" />
              )}
              <span>{copiedAction === 'sigma' ? 'Copied' : 'Copy Sigma'}</span>
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={handleDownloadMarkdown}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white transition-all cursor-pointer"
              title="Download Markdown summary"
            >
              <FileDown className="w-3.5 h-3.5 text-slate-400" />
              <span>Export .MD</span>
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-800 text-xs font-medium text-slate-300 hover:text-white transition-all cursor-pointer"
              title="Print or Save PDF"
            >
              <Printer className="w-3.5 h-3.5 text-slate-400" />
              <span>Print / PDF</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
