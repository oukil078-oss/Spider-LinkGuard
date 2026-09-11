import React from 'react';
import { ShieldCheck, ShieldAlert, CheckCircle, Activity, ExternalLink } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface ThreatIntelTabProps {
  report: ScanReport;
}

export const ThreatIntelTab: React.FC<ThreatIntelTabProps> = ({ report }) => {
  const intel = report.threatIntel;

  return (
    <div className="space-y-6">
      {/* 4 Threat Feed Header Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Feed 1: VirusTotal */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-medium">VirusTotal</span>
            <span
              className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                intel.virusTotal.positives > 0
                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/25'
                  : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25'
              }`}
            >
              {intel.virusTotal.positives > 0 ? 'Flagged' : 'Clean'}
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">
            {intel.virusTotal.positives} <span className="text-xs font-sans font-normal text-slate-500">/ {intel.virusTotal.total || 70} vendors</span>
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Antivirus engine detections
          </div>
        </div>

        {/* Feed 2: URLhaus (Abuse.ch) */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-medium">URLhaus (Abuse.ch)</span>
            <span
              className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                intel.urlhaus.detected
                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/25'
                  : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25'
              }`}
            >
              {intel.urlhaus.detected ? 'Malware Listed' : 'Not Listed'}
            </span>
          </div>
          <div className="text-base font-semibold text-slate-100 truncate">
            {intel.urlhaus.threat || 'Clean / Unlisted'}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            Status: <span className="text-slate-300">{intel.urlhaus.status || 'No active campaign'}</span>
          </div>
        </div>

        {/* Feed 3: urlscan.io */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-medium">urlscan.io</span>
            <span
              className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                intel.urlscan.malicious
                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/25'
                  : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25'
              }`}
            >
              {intel.urlscan.malicious ? 'Malicious' : 'Unflagged'}
            </span>
          </div>
          <div className="text-base font-semibold text-slate-100 truncate">
            {intel.urlscan.asn || 'Cloud Infrastructure'}
          </div>
          <div className="text-xs text-slate-400 mt-1 truncate">
            {intel.urlscan.asnName || 'Edge Network'}
          </div>
        </div>

        {/* Feed 4: Safe Browsing & PhishTank */}
        <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-medium">Safe Browsing & PhishTank</span>
            <span
              className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                intel.googleSafeBrowsing.detected || intel.phishTank.detected
                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/25'
                  : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25'
              }`}
            >
              {intel.googleSafeBrowsing.detected || intel.phishTank.detected
                ? 'Flagged'
                : 'Clear'}
            </span>
          </div>
          <div className="text-base font-semibold text-slate-100">
            {intel.phishTank.detected ? 'PhishTank Match' : 'Zero Reputation Flags'}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            GSB: {intel.googleSafeBrowsing.threatTypes.join(', ') || 'Clean'}
          </div>
        </div>
      </div>

      {/* Vendor Engine Matrix */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Antivirus Vendor Analysis ({intel.virusTotal.positives} Flagged)
            </h3>
          </div>
          <span className="text-xs text-slate-400">
            Scan Timestamp: {new Date(intel.virusTotal.scanDate || Date.now()).toLocaleTimeString()}
          </span>
        </div>

        {intel.virusTotal.engineResults && Object.keys(intel.virusTotal.engineResults).length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {Object.entries(intel.virusTotal.engineResults).map(([engine, data]) => {
              const isMalicious = data.category === 'malicious';
              return (
                <div
                  key={engine}
                  className={`p-3 rounded-xl border text-xs transition-colors ${
                    isMalicious
                      ? 'bg-rose-950/20 border-rose-700/40 text-rose-300'
                      : 'bg-slate-900/60 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-slate-200 truncate">{engine}</span>
                    {isMalicious ? (
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    ) : (
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    )}
                  </div>
                  <div className="text-[11px] truncate text-slate-400">
                    Result: <span className={isMalicious ? 'text-rose-400 font-semibold' : 'text-slate-500'}>{data.result}</span>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center p-8 text-xs text-slate-400">
            No specific vendor breakdown entries available for this target.
          </div>
        )}
      </div>
    </div>
  );
};
