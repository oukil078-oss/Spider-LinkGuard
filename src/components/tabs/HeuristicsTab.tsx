import React from 'react';
import { Binary, SpellCheck, AlertTriangle, ShieldCheck, Gauge } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface HeuristicsTabProps {
  report: ScanReport;
}

export const HeuristicsTab: React.FC<HeuristicsTabProps> = ({ report }) => {
  const { entropy, homoglyphs, normalization } = report;

  return (
    <div className="space-y-6">
      {/* Shannon Entropy Meters Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Query Entropy */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5">
              <Binary className="w-3.5 h-3.5 text-sky-400" />
              QUERY PARAMETER ENTROPY
            </span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                entropy.queryEntropy > 4.5
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-slate-800 text-slate-300'
              }`}
            >
              {entropy.queryEntropy > 4.5 ? 'HIGH ENTROPY' : 'NORMAL'}
            </span>
          </div>

          <div className="text-3xl font-mono font-black text-slate-100 my-2">
            {entropy.queryEntropy} <span className="text-xs font-normal text-slate-500">bits/byte</span>
          </div>

          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-850">
            <div
              className={`h-full ${
                entropy.queryEntropy > 4.5 ? 'bg-rose-500' : 'bg-sky-500'
              }`}
              style={{ width: `${Math.min(100, (entropy.queryEntropy / 8) * 100)}%` }}
            />
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-2">
            Threshold: &gt; 4.5 indicates encrypted/token payload
          </div>
        </div>

        {/* Path Entropy */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5">
              <Binary className="w-3.5 h-3.5 text-emerald-400" />
              PATH SEGMENT ENTROPY
            </span>
            <span className="text-xs font-mono text-slate-400">
              {entropy.pathEntropy > 4.2 ? 'ELEVATED' : 'STANDARD'}
            </span>
          </div>

          <div className="text-3xl font-mono font-black text-slate-100 my-2">
            {entropy.pathEntropy} <span className="text-xs font-normal text-slate-500">bits/byte</span>
          </div>

          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-850">
            <div
              className={`h-full ${
                entropy.pathEntropy > 4.2 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, (entropy.pathEntropy / 8) * 100)}%` }}
            />
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-2">
            Measures randomness in URI path structure
          </div>
        </div>

        {/* Full URL Entropy */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5">
              <Gauge className="w-3.5 h-3.5 text-purple-400" />
              AGGREGATE URL ENTROPY
            </span>
            <span className="text-xs font-mono text-slate-400">
              {entropy.fullUrlEntropy > 4.6 ? 'HIGH' : 'BALANCED'}
            </span>
          </div>

          <div className="text-3xl font-mono font-black text-slate-100 my-2">
            {entropy.fullUrlEntropy} <span className="text-xs font-normal text-slate-500">bits/byte</span>
          </div>

          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-850">
            <div
              className={`h-full ${
                entropy.fullUrlEntropy > 4.6 ? 'bg-rose-500' : 'bg-purple-500'
              }`}
              style={{ width: `${Math.min(100, (entropy.fullUrlEntropy / 8) * 100)}%` }}
            />
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-2">
            Global character set distribution Shannon test
          </div>
        </div>
      </div>

      {/* Entropy Findings Notes */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
        <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
          ENTROPY ANALYSIS FINDINGS
        </h4>
        <ul className="space-y-1 text-xs font-mono text-slate-300">
          {entropy.analysisNotes.map((note, idx) => (
            <li key={idx} className="flex items-start gap-2">
              <span className="text-sky-400">•</span>
              <span>{note}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Homoglyph & Typosquatting Section */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            <SpellCheck className="w-4 h-4 text-sky-400" />
            <span>HOMOGLYPH & TYPOSQUATTING BRAND IMPERSONATION INSPECTOR</span>
          </div>

          <span
            className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border uppercase ${
              homoglyphs.hasHomoglyphs
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
            }`}
          >
            {homoglyphs.hasHomoglyphs ? 'CONFUSABLES DETECTED' : 'CLEAN UNICODE'}
          </span>
        </div>

        <div className="mb-4">
          <p className="text-sm font-sans text-slate-200 leading-relaxed">
            {homoglyphs.explanation}
          </p>
          {homoglyphs.spoofedBrand && (
            <div className="mt-2 inline-flex items-center gap-2 px-3 py-1 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs font-mono">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>
                TARGET BRAND SPOOFED: <strong>{homoglyphs.spoofedBrand.toUpperCase()}</strong>
              </span>
            </div>
          )}
        </div>

        {homoglyphs.hasHomoglyphs && homoglyphs.details.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2.5 px-3">INDEX</th>
                  <th className="py-2.5 px-3">CHARACTER</th>
                  <th className="py-2.5 px-3">UNICODE</th>
                  <th className="py-2.5 px-3">LATIN COUNTERPART</th>
                  <th className="py-2.5 px-3">DESCRIPTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {homoglyphs.details.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/60">
                    <td className="py-2.5 px-3 font-bold text-slate-400">#{item.index}</td>
                    <td className="py-2.5 px-3 text-lg text-rose-400 font-bold">{item.char}</td>
                    <td className="py-2.5 px-3 text-sky-400 font-semibold">{item.unicode}</td>
                    <td className="py-2.5 px-3 text-emerald-400 font-bold">{item.latinEquivalent}</td>
                    <td className="py-2.5 px-3 text-slate-300">{item.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
