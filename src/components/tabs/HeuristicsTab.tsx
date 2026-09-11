import React from 'react';
import { Binary, SpellCheck, AlertTriangle, ShieldCheck, Gauge } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface HeuristicsTabProps {
  report: ScanReport;
}

export const HeuristicsTab: React.FC<HeuristicsTabProps> = ({ report }) => {
  const { entropy, homoglyphs } = report;

  return (
    <div className="space-y-6">
      {/* Shannon Entropy Meters */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Query Entropy */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium">
              <Binary className="w-3.5 h-3.5 text-sky-400" />
              Query Parameters Entropy
            </span>
            <span
              className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                entropy.queryEntropy > 4.5
                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/25'
                  : 'bg-slate-800 text-slate-300'
              }`}
            >
              {entropy.queryEntropy > 4.5 ? 'High Entropy' : 'Normal'}
            </span>
          </div>

          <div className="text-3xl font-bold font-mono text-slate-100 my-2">
            {entropy.queryEntropy} <span className="text-xs font-normal text-slate-500">bits/byte</span>
          </div>

          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div
              className={`h-full ${
                entropy.queryEntropy > 4.5 ? 'bg-rose-500' : 'bg-sky-500'
              }`}
              style={{ width: `${Math.min(100, (entropy.queryEntropy / 8) * 100)}%` }}
            />
          </div>
          <div className="text-xs text-slate-400 mt-2">
            Values &gt; 4.5 indicate encrypted tokens or obfuscated payloads
          </div>
        </div>

        {/* Path Entropy */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium">
              <Binary className="w-3.5 h-3.5 text-emerald-400" />
              Path Segment Entropy
            </span>
            <span className="text-xs text-slate-400">
              {entropy.pathEntropy > 4.2 ? 'Elevated' : 'Standard'}
            </span>
          </div>

          <div className="text-3xl font-bold font-mono text-slate-100 my-2">
            {entropy.pathEntropy} <span className="text-xs font-normal text-slate-500">bits/byte</span>
          </div>

          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div
              className={`h-full ${
                entropy.pathEntropy > 4.2 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, (entropy.pathEntropy / 8) * 100)}%` }}
            />
          </div>
          <div className="text-xs text-slate-400 mt-2">
            Measures character randomness in URI path elements
          </div>
        </div>

        {/* Full URL Entropy */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium">
              <Gauge className="w-3.5 h-3.5 text-purple-400" />
              Aggregate URL Entropy
            </span>
            <span className="text-xs text-slate-400">
              {entropy.fullUrlEntropy > 4.6 ? 'High' : 'Balanced'}
            </span>
          </div>

          <div className="text-3xl font-bold font-mono text-slate-100 my-2">
            {entropy.fullUrlEntropy} <span className="text-xs font-normal text-slate-500">bits/byte</span>
          </div>

          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div
              className={`h-full ${
                entropy.fullUrlEntropy > 4.6 ? 'bg-rose-500' : 'bg-purple-500'
              }`}
              style={{ width: `${Math.min(100, (entropy.fullUrlEntropy / 8) * 100)}%` }}
            />
          </div>
          <div className="text-xs text-slate-400 mt-2">
            Comprehensive character set distribution Shannon test
          </div>
        </div>
      </div>

      {/* Entropy Notes */}
      {entropy.analysisNotes.length > 0 && (
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <h4 className="text-sm font-semibold text-slate-100 mb-2">
            Entropy Observations
          </h4>
          <ul className="space-y-1.5 text-xs text-slate-300">
            {entropy.analysisNotes.map((note, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-sky-400 mt-0.5">•</span>
                <span>{note}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Homoglyph & Typosquatting Section */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <SpellCheck className="w-4 h-4 text-sky-400" />
            <span>Homoglyph & Unicode Typosquatting Analysis</span>
          </div>

          <span
            className={`px-3 py-0.5 rounded-full text-xs font-semibold border ${
              homoglyphs.hasHomoglyphs
                ? 'bg-rose-500/10 text-rose-400 border-rose-500/25'
                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
            }`}
          >
            {homoglyphs.hasHomoglyphs ? 'Lookalikes Detected' : 'Clean Unicode'}
          </span>
        </div>

        <div className="mb-4">
          <p className="text-sm text-slate-300 leading-relaxed">
            {homoglyphs.explanation}
          </p>
          {homoglyphs.spoofedBrand && (
            <div className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/25 text-rose-300 text-xs">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              <span>
                Target Brand Spoofed: <strong className="uppercase">{homoglyphs.spoofedBrand}</strong>
              </span>
            </div>
          )}
        </div>

        {homoglyphs.hasHomoglyphs && homoglyphs.details.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400 font-medium">
                <tr>
                  <th className="py-2.5 px-3">Position</th>
                  <th className="py-2.5 px-3">Character</th>
                  <th className="py-2.5 px-3">Unicode Code Point</th>
                  <th className="py-2.5 px-3">Latin Equivalent</th>
                  <th className="py-2.5 px-3">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {homoglyphs.details.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40">
                    <td className="py-2.5 px-3 text-slate-400 font-mono">#{item.index}</td>
                    <td className="py-2.5 px-3 text-base text-rose-400 font-bold">{item.char}</td>
                    <td className="py-2.5 px-3 text-sky-400 font-mono">{item.unicode}</td>
                    <td className="py-2.5 px-3 text-emerald-400 font-semibold">{item.latinEquivalent}</td>
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
