import React, { useState } from 'react';
import { Globe, Server, AlertCircle, ShieldAlert, Cpu, Brain, Database, ShieldCheck, Copy, Check } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface OverviewTabProps {
  report: ScanReport;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ report }) => {
  const norm = report.normalization;
  const scoring = report.scoring;
  const intel = report.threatIntel;
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyValue = (val: string, key: string) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Destination Host */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium">
              <Globe className="w-3.5 h-3.5 text-sky-400" />
              Destination Host
            </span>
            <span
              className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                norm.isIp
                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/25'
                  : 'bg-slate-800 text-slate-300'
              }`}
            >
              {norm.isIp ? `IP (${norm.ipVersion})` : 'Domain'}
            </span>
          </div>
          <div className="text-base font-semibold text-slate-100 truncate" title={norm.hostname}>
            {norm.hostname}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            TLD: <span className={norm.isSuspiciousTld ? 'text-rose-400 font-semibold' : 'text-slate-300 font-mono'}>.{norm.tld || 'none'}</span>
            {norm.isSuspiciousTld && ' (High Abuse TLD)'}
          </div>
        </div>

        {/* Card 2: Protocol & Port */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium">
              <Server className="w-3.5 h-3.5 text-emerald-400" />
              Protocol & Port
            </span>
            <span className="text-emerald-400 text-xs font-semibold uppercase">
              {norm.scheme}
            </span>
          </div>
          <div className="text-base font-semibold text-slate-100">
            Port {norm.port}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Redirects: <span className="text-slate-200 font-semibold">{report.redirectChain.totalHops}</span>
            {report.redirectChain.evasionDetected && (
              <span className="text-rose-400 font-semibold ml-1.5">• Evasion Detected</span>
            )}
          </div>
        </div>

        {/* Card 3: Network & ASN */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium">
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              Network & ASN
            </span>
            <span className="text-slate-400 text-xs">
              {intel.urlscan.country || 'Global'}
            </span>
          </div>
          <div className="text-base font-semibold text-slate-100 truncate">
            {intel.urlscan.asn || 'Cloud Network'}
          </div>
          <div className="text-xs text-slate-400 mt-1 truncate" title={intel.urlscan.asnName}>
            {intel.urlscan.asnName || 'Hosting Infrastructure'}
          </div>
        </div>

        {/* Card 4: Credential Harvester */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-medium">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              Credential Forms
            </span>
            <span
              className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                report.domSandbox.hasCredentialHarvester
                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/25'
                  : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25'
              }`}
            >
              {report.domSandbox.hasCredentialHarvester ? 'Detected' : 'Clear'}
            </span>
          </div>
          <div className="text-base font-semibold text-slate-100">
            {report.domSandbox.forms.length} {report.domSandbox.forms.length === 1 ? 'Form' : 'Forms'} Found
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Scripts: <span className="text-slate-200">{report.domSandbox.scripts.length}</span> •
            Links: <span className="text-slate-200">{report.domSandbox.domSummary.linksCount}</span>
          </div>
        </div>
      </div>

      {/* Machine Learning & Threat Dataset Assessment */}
      {report.mlClassification && (
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 mb-4 border-b border-slate-800/80">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
                <Brain className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  Machine Learning Threat Classification
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Trained on Kaggle Malicious URLs dataset (651k samples) and curated threat signatures
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-medium">Predicted Class:</span>
              <span
                className={`px-3 py-1 rounded-full text-xs font-semibold capitalize border ${
                  report.mlClassification.predictedCategory === 'malware'
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/25'
                    : report.mlClassification.predictedCategory === 'phishing'
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/25'
                    : report.mlClassification.predictedCategory === 'defacement'
                    ? 'bg-purple-500/10 text-purple-400 border-purple-500/25'
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
                }`}
              >
                {report.mlClassification.predictedCategory}
              </span>
              <span className="text-xs px-2.5 py-1 rounded-lg bg-slate-800 text-slate-200 font-semibold">
                {report.mlClassification.confidence}% Confidence
              </span>
            </div>
          </div>

          {/* Dataset Signature Alert if matched */}
          {report.datasetIntel?.matched && (
            <div className="mb-5 p-4 rounded-xl bg-rose-500/10 border border-rose-500/25 text-xs flex items-start gap-3">
              <Database className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-rose-300 font-semibold">
                    Known Threat Signature Match:
                  </span>
                  <span className="px-2 py-0.5 rounded bg-rose-950/80 text-rose-200 border border-rose-800/80 font-mono text-[11px]">
                    {report.datasetIntel.pattern}
                  </span>
                  <span className="text-slate-400 text-[11px]">
                    Source: {report.datasetIntel.source}
                  </span>
                </div>
                <p className="text-slate-300 mt-1 leading-relaxed">
                  {report.datasetIntel.description}
                </p>
              </div>
            </div>
          )}

          {/* Probability Distribution */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
            <div className="p-3.5 bg-slate-900/60 rounded-xl border border-slate-800/80">
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-slate-400">Clean / Benign</span>
                <span className="text-emerald-400 font-semibold">
                  {report.mlClassification.classProbabilities.benign}%
                </span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-emerald-400 h-full rounded-full transition-all duration-500"
                  style={{ width: `${report.mlClassification.classProbabilities.benign}%` }}
                />
              </div>
            </div>

            <div className="p-3.5 bg-slate-900/60 rounded-xl border border-slate-800/80">
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-slate-400">Phishing</span>
                <span className="text-amber-400 font-semibold">
                  {report.mlClassification.classProbabilities.phishing}%
                </span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-amber-400 h-full rounded-full transition-all duration-500"
                  style={{ width: `${report.mlClassification.classProbabilities.phishing}%` }}
                />
              </div>
            </div>

            <div className="p-3.5 bg-slate-900/60 rounded-xl border border-slate-800/80">
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-slate-400">Malware</span>
                <span className="text-rose-400 font-semibold">
                  {report.mlClassification.classProbabilities.malware}%
                </span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-rose-400 h-full rounded-full transition-all duration-500"
                  style={{ width: `${report.mlClassification.classProbabilities.malware}%` }}
                />
              </div>
            </div>

            <div className="p-3.5 bg-slate-900/60 rounded-xl border border-slate-800/80">
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-slate-400">Defacement</span>
                <span className="text-purple-400 font-semibold">
                  {report.mlClassification.classProbabilities.defacement}%
                </span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-purple-400 h-full rounded-full transition-all duration-500"
                  style={{ width: `${report.mlClassification.classProbabilities.defacement}%` }}
                />
              </div>
            </div>
          </div>

          {/* Extracted Feature Indicators */}
          <div>
            <span className="text-xs font-medium text-slate-400 block mb-2">
              Detected Anomalies & Characteristics:
            </span>
            <div className="flex flex-wrap gap-2">
              {report.mlClassification.featuresTriggered.length > 0 ? (
                report.mlClassification.featuresTriggered.map((feat, i) => (
                  <span
                    key={i}
                    className="px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 flex items-center gap-1.5"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                    {feat}
                  </span>
                ))
              ) : (
                <span className="text-xs text-emerald-400 flex items-center gap-1.5 py-1">
                  <ShieldCheck className="w-4 h-4" />
                  No suspicious lexical or structural anomalies detected.
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Risk Factors Breakdown Table */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Risk Scoring Breakdown & Evidence
            </h3>
          </div>
          <span className="text-xs text-slate-400">
            Calculated Risk: <span className="text-sky-300 font-semibold">{scoring.overallScore} / 100</span>
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-medium">
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Max Weight</th>
                <th className="py-2.5 px-3">Points</th>
                <th className="py-2.5 px-3">Observed Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scoring.breakdown.map((factor, idx) => {
                const getBadge = (s: string) => {
                  switch (s) {
                    case 'critical':
                      return 'bg-rose-500/10 text-rose-400 border-rose-500/25';
                    case 'malicious':
                      return 'bg-red-500/10 text-red-400 border-red-500/25';
                    case 'suspicious':
                      return 'bg-amber-500/10 text-amber-400 border-amber-500/25';
                    default:
                      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25';
                  }
                };

                return (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-3 font-semibold text-slate-200">{factor.category}</td>
                    <td className="py-3 px-3">
                      <span className={`inline-block px-2 py-0.5 rounded-full text-[11px] font-semibold capitalize border ${getBadge(factor.severity)}`}>
                        {factor.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-400">{factor.weight} pts</td>
                    <td className="py-3 px-3 font-semibold text-sky-400">+{factor.score}</td>
                    <td className="py-3 px-3 text-slate-300 leading-relaxed max-w-xl">
                      {factor.description}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Target Indicators of Compromise (IOCs) */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-100 mb-3">
          Indicators of Compromise (IOCs)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3.5 bg-slate-900/80 rounded-xl border border-slate-800/80 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <span className="text-slate-400 font-medium block mb-1">Defanged URL (Safe for sharing):</span>
              <span className="text-sky-300 font-mono text-xs select-all break-all block">{norm.defangedUrl}</span>
            </div>
            <button
              onClick={() => copyValue(norm.defangedUrl, 'defanged')}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg bg-slate-800/60 hover:bg-slate-750 transition-colors shrink-0"
              title="Copy defanged URL"
            >
              {copiedKey === 'defanged' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          <div className="p-3.5 bg-slate-900/80 rounded-xl border border-slate-800/80 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <span className="text-slate-400 font-medium block mb-1">Canonical Active URL:</span>
              <span className="text-slate-200 font-mono text-xs select-all break-all block">{norm.canonicalUrl}</span>
            </div>
            <button
              onClick={() => copyValue(norm.canonicalUrl, 'canonical')}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg bg-slate-800/60 hover:bg-slate-750 transition-colors shrink-0"
              title="Copy canonical URL"
            >
              {copiedKey === 'canonical' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
