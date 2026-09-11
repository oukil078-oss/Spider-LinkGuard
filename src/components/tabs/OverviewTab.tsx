import React from 'react';
import { Globe, Server, AlertCircle, ShieldAlert, Cpu } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface OverviewTabProps {
  report: ScanReport;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ report }) => {
  const norm = report.normalization;
  const scoring = report.scoring;
  const intel = report.threatIntel;

  return (
    <div className="space-y-6">
      {/* Top Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Hostname & Type */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-sky-400" />
              DESTINATION HOST
            </span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                norm.isIp
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  : 'bg-slate-800 text-slate-300'
              }`}
            >
              {norm.isIp ? `IP (${norm.ipVersion})` : 'DOMAIN'}
            </span>
          </div>
          <div className="text-base font-mono font-bold text-slate-100 truncate" title={norm.hostname}>
            {norm.hostname}
          </div>
          <div className="text-xs font-mono text-slate-500 mt-1">
            TLD: <span className={norm.isSuspiciousTld ? 'text-rose-400 font-bold' : 'text-slate-400'}>.{norm.tld || 'none'}</span>
            {norm.isSuspiciousTld && ' (High Abuse TLD)'}
          </div>
        </div>

        {/* Card 2: Port & Protocol */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-emerald-400" />
              PROTOCOL / PORT
            </span>
            <span className="text-emerald-400 text-xs font-mono font-bold">
              {norm.scheme.toUpperCase()}
            </span>
          </div>
          <div className="text-base font-mono font-bold text-slate-100">
            Port {norm.port}
          </div>
          <div className="text-xs font-mono text-slate-500 mt-1">
            Hops: <span className="text-slate-300 font-semibold">{report.redirectChain.totalHops}</span>
            {report.redirectChain.evasionDetected && (
              <span className="text-rose-400 font-bold ml-1.5">• Evasion Alert</span>
            )}
          </div>
        </div>

        {/* Card 3: Geo & ASN */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              INFRASTRUCTURE / ASN
            </span>
            <span className="text-slate-400 text-xs font-mono">
              {intel.urlscan.country || 'Global'}
            </span>
          </div>
          <div className="text-base font-mono font-bold text-slate-100 truncate">
            {intel.urlscan.asn || 'AS-UNKNOWN'}
          </div>
          <div className="text-xs font-mono text-slate-400 mt-1 truncate" title={intel.urlscan.asnName}>
            {intel.urlscan.asnName || 'Cloud Edge / Hosting Provider'}
          </div>
        </div>

        {/* Card 4: DOM Harvest State */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span className="flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              CREDENTIAL HARVESTER
            </span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                report.domSandbox.hasCredentialHarvester
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}
            >
              {report.domSandbox.hasCredentialHarvester ? 'DETECTED' : 'CLEAR'}
            </span>
          </div>
          <div className="text-base font-mono font-bold text-slate-100">
            {report.domSandbox.forms.length} Forms Extracted
          </div>
          <div className="text-xs font-mono text-slate-500 mt-1">
            Scripts: <span className="text-slate-300">{report.domSandbox.scripts.length}</span> •
            Links: <span className="text-slate-300">{report.domSandbox.domSummary.linksCount}</span>
          </div>
        </div>
      </div>

      {/* Threat Scoring Factors Table */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-sky-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              THREAT SCORING MATRIX BREAKDOWN (RISK FACTORS)
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            TOTAL RISK: <span className="text-sky-300 font-bold">{scoring.overallScore} / 100</span>
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">CATEGORY</th>
                <th className="py-2.5 px-3">SEVERITY</th>
                <th className="py-2.5 px-3">WEIGHT</th>
                <th className="py-2.5 px-3">POINTS</th>
                <th className="py-2.5 px-3 font-sans">FINDING / EVIDENCE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {scoring.breakdown.map((factor, idx) => {
                const getBadge = (s: string) => {
                  switch (s) {
                    case 'critical':
                      return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
                    case 'malicious':
                      return 'bg-red-500/20 text-red-300 border-red-500/40';
                    case 'suspicious':
                      return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
                    default:
                      return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
                  }
                };

                return (
                  <tr key={idx} className="hover:bg-slate-900/60 transition-colors">
                    <td className="py-3 px-3 font-bold text-slate-200">{factor.category}</td>
                    <td className="py-3 px-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getBadge(
                          factor.severity
                        )}`}
                      >
                        {factor.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-400">Max {factor.weight}</td>
                    <td className="py-3 px-3 font-bold text-sky-400">+{factor.score}</td>
                    <td className="py-3 px-3 font-sans text-slate-300 leading-relaxed">
                      {factor.description}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Target IOC Representations Strip */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5">
        <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-3">
          STANDARDIZED INDICATORS OF COMPROMISE (IOCS)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-900/90 rounded-lg border border-slate-800">
            <span className="text-slate-500 block mb-1">DEFANGED URL (SAFE SHARING):</span>
            <span className="text-sky-300 select-all break-all">{norm.defangedUrl}</span>
          </div>

          <div className="p-3 bg-slate-900/90 rounded-lg border border-slate-800">
            <span className="text-slate-500 block mb-1">CANONICAL ACTIVE URL:</span>
            <span className="text-rose-300 select-all break-all">{norm.canonicalUrl}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
