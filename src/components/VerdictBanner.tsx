import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  ShieldX,
  Flame,
  FileDown,
  Copy,
  Check,
  Printer,
  FileCode,
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
          icon: <Flame className="w-8 h-8 text-rose-500 animate-pulse" />,
          bgColor: 'bg-rose-950/40',
          borderColor: 'border-rose-600',
          textColor: 'text-rose-400',
          badgeBg: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          glow: 'shadow-rose-950/60',
          barColor: 'bg-gradient-to-r from-amber-500 via-rose-500 to-purple-600',
        };
      case 'MALICIOUS':
        return {
          icon: <ShieldX className="w-8 h-8 text-red-500" />,
          bgColor: 'bg-red-950/40',
          borderColor: 'border-red-600',
          textColor: 'text-red-400',
          badgeBg: 'bg-red-500/20 text-red-300 border-red-500/40',
          glow: 'shadow-red-950/60',
          barColor: 'bg-red-500',
        };
      case 'SUSPICIOUS':
        return {
          icon: <AlertTriangle className="w-8 h-8 text-amber-500" />,
          bgColor: 'bg-amber-950/40',
          borderColor: 'border-amber-600',
          textColor: 'text-amber-400',
          badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          glow: 'shadow-amber-950/60',
          barColor: 'bg-amber-500',
        };
      default:
        return {
          icon: <ShieldCheck className="w-8 h-8 text-emerald-400" />,
          bgColor: 'bg-emerald-950/40',
          borderColor: 'border-emerald-600',
          textColor: 'text-emerald-400',
          badgeBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
          glow: 'shadow-emerald-950/60',
          barColor: 'bg-emerald-500',
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
    <div
      className={`rounded-xl border ${config.borderColor} ${config.bgColor} p-6 shadow-2xl relative overflow-hidden transition-all`}
    >
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
        {/* Left Section: Icon & Verdict */}
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 shadow-inner">
            {config.icon}
          </div>

          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className={`text-2xl font-mono font-extrabold tracking-wider ${config.textColor}`}>
                {verdict}
              </span>
              <span
                className={`px-3 py-0.5 rounded-full text-xs font-mono font-bold border uppercase ${config.badgeBg}`}
              >
                VERDICT RESOLVED
              </span>
              <span className="text-xs font-mono text-slate-400">
                ID: <span className="text-slate-200">{report.id}</span>
              </span>
            </div>

            <p className="text-sm text-slate-300 font-sans max-w-2xl leading-relaxed">
              {verdictReason}
            </p>

            <div className="flex flex-wrap items-center gap-2 mt-3 text-xs font-mono text-slate-400">
              <span>CANONICAL:</span>
              <span className="text-sky-300 bg-slate-900/90 px-2 py-0.5 rounded border border-slate-800 break-all">
                {report.normalization.canonicalUrl}
              </span>
            </div>
          </div>
        </div>

        {/* Center: 0-100 Score Dial / Meter */}
        <div className="flex flex-col items-center justify-center min-w-[170px] bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-inner">
          <span className="text-[11px] font-mono uppercase text-slate-400 font-semibold mb-1">
            THREAT RISK SCORE
          </span>
          <div className="flex items-baseline gap-1">
            <span className={`text-4xl font-mono font-black ${config.textColor}`}>
              {overallScore}
            </span>
            <span className="text-sm font-mono text-slate-500">/100</span>
          </div>

          {/* Progress Bar */}
          <div className="w-full h-2 bg-slate-950 rounded-full mt-2.5 overflow-hidden border border-slate-800">
            <div
              className={`h-full ${config.barColor} transition-all duration-1000 ease-out`}
              style={{ width: `${Math.max(5, overallScore)}%` }}
            />
          </div>
        </div>

        {/* Right Section: Fast Action Buttons */}
        <div className="flex flex-col sm:flex-row lg:flex-col gap-2 w-full lg:w-auto shrink-0">
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => copyText(report.normalization.defangedUrl, 'defanged')}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-750 text-xs font-mono text-slate-200 hover:text-white transition-all cursor-pointer shadow-sm"
              title="Copy defanged URL for safe sharing"
            >
              {copiedAction === 'defanged' ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5 text-sky-400" />
              )}
              <span>{copiedAction === 'defanged' ? 'COPIED!' : 'DEFANG URL'}</span>
            </button>

            <button
              onClick={() => copyText(report.rules.sigma, 'sigma')}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-750 text-xs font-mono text-slate-200 hover:text-white transition-all cursor-pointer shadow-sm"
              title="Copy Sigma Log Detection Rule"
            >
              {copiedAction === 'sigma' ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <FileCode className="w-3.5 h-3.5 text-purple-400" />
              )}
              <span>{copiedAction === 'sigma' ? 'COPIED!' : 'SIGMA RULE'}</span>
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={handleDownloadMarkdown}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-750 text-xs font-mono text-slate-200 hover:text-white transition-all cursor-pointer shadow-sm"
              title="Download Executive Markdown Report"
            >
              <FileDown className="w-3.5 h-3.5 text-emerald-400" />
              <span>EXPORT .MD</span>
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-750 text-xs font-mono text-slate-200 hover:text-white transition-all cursor-pointer shadow-sm"
              title="Print or Save PDF report"
            >
              <Printer className="w-3.5 h-3.5 text-slate-400" />
              <span>PRINT / PDF</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
