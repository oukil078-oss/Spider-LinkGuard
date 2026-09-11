import React, { useState } from 'react';
import { GitCommit, AlertTriangle, ArrowRight, Clock, ShieldCheck, ChevronDown, ChevronRight } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface RedirectTabProps {
  report: ScanReport;
}

export const RedirectTab: React.FC<RedirectTabProps> = ({ report }) => {
  const [expandedHop, setExpandedHop] = useState<number | null>(0);
  const chain = report.redirectChain;

  return (
    <div className="space-y-6">
      {/* Evasion Summary Header */}
      <div
        className={`rounded-xl border p-5 shadow-lg ${
          chain.evasionDetected
            ? 'bg-rose-950/30 border-rose-600/70 text-rose-300'
            : 'bg-[#0b101b] border-slate-800 text-slate-300'
        }`}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            {chain.evasionDetected ? (
              <AlertTriangle className="w-5 h-5 text-rose-400 animate-pulse" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            )}
            <h3 className="font-mono font-bold text-sm tracking-wider uppercase">
              {chain.evasionDetected
                ? 'EVASION / CLOAKING INDICATORS IDENTIFIED'
                : 'REDIRECT CHAIN TRAVERSED • NORMAL BEHAVIOR'}
            </h3>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 font-bold">
            {chain.totalHops} {chain.totalHops === 1 ? 'HOP' : 'HOPS TOTAL'}
          </span>
        </div>

        {chain.evasionDetected && (
          <ul className="mt-3 space-y-1.5 text-xs font-sans text-slate-200 list-disc list-inside">
            {chain.evasionReasons.map((reason, idx) => (
              <li key={idx} className="leading-relaxed">
                <span className="font-mono text-rose-300 font-semibold">{reason}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Visual Hop Pipeline */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-6">
          REDIRECT TRAVERSAL GRAPH & HEADER INSPECTION
        </h4>

        <div className="space-y-4">
          {chain.hops.map((hop, idx) => {
            const isExpanded = expandedHop === idx;
            const isLast = idx === chain.hops.length - 1;

            const getStatusColor = (code: number) => {
              if (code >= 200 && code < 300) return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
              if (code >= 300 && code < 400) return 'bg-sky-500/20 text-sky-300 border-sky-500/40';
              return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
            };

            return (
              <div key={idx} className="relative">
                {/* Connector line between hops */}
                {!isLast && (
                  <div className="absolute left-5 top-12 bottom-[-16px] w-0.5 bg-slate-800 z-0"></div>
                )}

                <div className="relative z-10 bg-slate-900/90 border border-slate-800 rounded-xl p-4 transition-all hover:border-slate-700">
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-slate-950 border border-slate-750 flex items-center justify-center font-mono font-bold text-xs text-sky-400 shrink-0">
                        #{hop.hopIndex}
                      </div>

                      <div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${getStatusColor(
                              hop.statusCode
                            )}`}
                          >
                            HTTP {hop.statusCode} {hop.statusText}
                          </span>
                          {hop.isMetaRefresh && (
                            <span className="text-[10px] font-mono bg-purple-950/60 text-purple-300 border border-purple-800 px-1.5 py-0.5 rounded">
                              META-REFRESH
                            </span>
                          )}
                          {hop.isJsRedirect && (
                            <span className="text-[10px] font-mono bg-amber-950/60 text-amber-300 border border-amber-800 px-1.5 py-0.5 rounded">
                              JS LOCATION
                            </span>
                          )}
                        </div>
                        <div className="text-sm font-mono text-slate-200 mt-1 break-all select-all">
                          {hop.url}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 text-xs font-mono text-slate-400 shrink-0 self-end md:self-center">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        {hop.latencyMs}ms
                      </span>
                      <button
                        onClick={() => setExpandedHop(isExpanded ? null : idx)}
                        className="flex items-center gap-1 text-sky-400 hover:text-sky-300 cursor-pointer"
                      >
                        <span>{isExpanded ? 'HIDE HEADERS' : 'VIEW HEADERS'}</span>
                        {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Header View */}
                  {isExpanded && (
                    <div className="mt-4 pt-3 border-t border-slate-800 text-xs font-mono space-y-2">
                      <div className="text-[11px] text-slate-500 font-bold uppercase">
                        RESPONSE HEADERS ({Object.keys(hop.headers).length}):
                      </div>
                      <div className="bg-slate-950 rounded-lg p-3 border border-slate-850 overflow-x-auto max-h-60">
                        {Object.entries(hop.headers).map(([k, v]) => (
                          <div key={k} className="py-0.5 leading-relaxed">
                            <span className="text-sky-400">{k}:</span>{' '}
                            <span className="text-slate-300">{v}</span>
                          </div>
                        ))}
                      </div>

                      {hop.cookiesSet.length > 0 && (
                        <div className="mt-2">
                          <span className="text-slate-500 block text-[11px] font-bold uppercase mb-1">
                            COOKIES ISSUED:
                          </span>
                          <div className="bg-slate-950 rounded p-2 border border-slate-850 text-amber-300">
                            {hop.cookiesSet.join(' | ')}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
