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
        className={`rounded-2xl border p-5 shadow-sm ${
          chain.evasionDetected
            ? 'bg-rose-950/20 border-rose-800/40 text-rose-200'
            : 'bg-[#0f1422] border-slate-800/80 text-slate-200'
        }`}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            {chain.evasionDetected ? (
              <AlertTriangle className="w-5 h-5 text-rose-400" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            )}
            <h3 className="font-semibold text-sm">
              {chain.evasionDetected
                ? 'Evasion & Cloaking Indicators Identified'
                : 'Redirect Chain Verified — Standard Routing'}
            </h3>
          </div>
          <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 font-medium">
            {chain.totalHops} {chain.totalHops === 1 ? 'Hop' : 'Hops Total'}
          </span>
        </div>

        {chain.evasionDetected && (
          <ul className="mt-3 space-y-1 text-xs text-slate-300 list-disc list-inside">
            {chain.evasionReasons.map((reason, idx) => (
              <li key={idx} className="leading-relaxed">
                <span className="text-rose-300 font-medium">{reason}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Visual Hop Pipeline */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <h4 className="text-sm font-semibold text-slate-100 mb-6">
          Redirect Traversal & Response Headers
        </h4>

        <div className="space-y-4">
          {chain.hops.map((hop, idx) => {
            const isExpanded = expandedHop === idx;
            const isLast = idx === chain.hops.length - 1;

            const getStatusBadge = (code: number) => {
              if (code >= 200 && code < 300) return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25';
              if (code >= 300 && code < 400) return 'bg-sky-500/10 text-sky-400 border-sky-500/25';
              return 'bg-rose-500/10 text-rose-400 border-rose-500/25';
            };

            return (
              <div key={idx} className="relative">
                {!isLast && (
                  <div className="absolute left-4 top-12 bottom-[-16px] w-0.5 bg-slate-800 z-0" />
                )}

                <div className="relative z-10 bg-slate-900/70 border border-slate-800/90 rounded-xl p-4 transition-all hover:border-slate-700">
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
                    <div className="flex items-start gap-3 min-w-0 flex-1">
                      <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center font-mono font-bold text-xs text-sky-400 shrink-0">
                        #{hop.hopIndex}
                      </div>

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${getStatusBadge(hop.statusCode)}`}>
                            HTTP {hop.statusCode} {hop.statusText}
                          </span>
                          {hop.isMetaRefresh && (
                            <span className="text-[11px] bg-purple-950/60 text-purple-300 border border-purple-800/80 px-2 py-0.5 rounded-full">
                              Meta-Refresh
                            </span>
                          )}
                          {hop.isJsRedirect && (
                            <span className="text-[11px] bg-amber-950/60 text-amber-300 border border-amber-800/80 px-2 py-0.5 rounded-full">
                              JS Location
                            </span>
                          )}
                        </div>
                        <div className="text-xs font-mono text-slate-200 break-all select-all">
                          {hop.url}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 text-xs text-slate-400 shrink-0 self-end md:self-center">
                      <span className="flex items-center gap-1 font-mono">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        {hop.latencyMs}ms
                      </span>
                      <button
                        onClick={() => setExpandedHop(isExpanded ? null : idx)}
                        className="flex items-center gap-1 text-sky-400 hover:text-sky-300 font-medium cursor-pointer"
                      >
                        <span>{isExpanded ? 'Hide Headers' : 'View Headers'}</span>
                        {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Headers */}
                  {isExpanded && (
                    <div className="mt-4 pt-3 border-t border-slate-800 text-xs space-y-2">
                      <div className="text-xs text-slate-400 font-medium">
                        Response Headers ({Object.keys(hop.headers).length}):
                      </div>
                      <div className="bg-slate-950 rounded-xl p-3 border border-slate-800/80 font-mono text-xs overflow-x-auto max-h-60">
                        {Object.entries(hop.headers).map(([k, v]) => (
                          <div key={k} className="py-0.5">
                            <span className="text-sky-400">{k}:</span>{' '}
                            <span className="text-slate-300">{v}</span>
                          </div>
                        ))}
                      </div>

                      {hop.cookiesSet.length > 0 && (
                        <div className="mt-2">
                          <span className="text-slate-400 font-medium block text-xs mb-1">
                            Cookies Set:
                          </span>
                          <div className="bg-slate-950 rounded-xl p-2.5 border border-slate-800/80 text-amber-300 font-mono text-xs">
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
