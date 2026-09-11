import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle, ExternalLink, Activity } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface ThreatIntelTabProps {
  report: ScanReport;
}

export const ThreatIntelTab: React.FC<ThreatIntelTabProps> = ({ report }) => {
  const intel = report.threatIntel;

  return (
    <div className="space-y-6">
      {/* 4 Threat Feed Header Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Feed 1: VirusTotal */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>VIRUSTOTAL v3</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                intel.virusTotal.positives > 0
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}
            >
              {intel.virusTotal.positives > 0 ? 'FLAGGED' : 'CLEAN'}
            </span>
          </div>
          <div className="text-xl font-mono font-extrabold text-slate-100">
            {intel.virusTotal.positives} / {intel.virusTotal.total}
          </div>
          <div className="text-xs font-sans text-slate-400 mt-1">
            AV vendors flagged as malicious/suspicious
          </div>
        </div>

        {/* Feed 2: URLhaus (Abuse.ch) */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>URLHAUS (ABUSE.CH)</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                intel.urlhaus.detected
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}
            >
              {intel.urlhaus.detected ? 'CONFIRMED MALWARE' : 'NOT LISTED'}
            </span>
          </div>
          <div className="text-base font-mono font-bold text-slate-100 truncate">
            {intel.urlhaus.threat || 'No Active Threat'}
          </div>
          <div className="text-xs font-sans text-slate-400 mt-1">
            Status: <span className="font-mono text-slate-300">{intel.urlhaus.status || 'Clean'}</span>
          </div>
        </div>

        {/* Feed 3: urlscan.io */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>URLSCAN.IO</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                intel.urlscan.malicious
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}
            >
              {intel.urlscan.malicious ? 'MALICIOUS' : 'UNFLAGGED'}
            </span>
          </div>
          <div className="text-base font-mono font-bold text-slate-100 truncate">
            {intel.urlscan.asn || 'AS-Edge'}
          </div>
          <div className="text-xs font-sans text-slate-400 mt-1 truncate">
            {intel.urlscan.asnName || 'Hosting Infrastructure'}
          </div>
        </div>

        {/* Feed 4: Safe Browsing & PhishTank */}
        <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
            <span>GSB & PHISHTANK</span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                intel.googleSafeBrowsing.detected || intel.phishTank.detected
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}
            >
              {intel.googleSafeBrowsing.detected || intel.phishTank.detected
                ? 'PHISH DETECTED'
                : 'VERIFIED CLEAR'}
            </span>
          </div>
          <div className="text-base font-mono font-bold text-slate-100">
            {intel.phishTank.detected ? 'PhishTank Match' : 'Zero Reputation Flags'}
          </div>
          <div className="text-xs font-sans text-slate-400 mt-1">
            GSB: {intel.googleSafeBrowsing.threatTypes.join(', ') || 'Clean'}
          </div>
        </div>
      </div>

      {/* VirusTotal Vendor Engine Matrix Grid */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            <Activity className="w-4 h-4 text-sky-400" />
            <span>VIRUSTOTAL ENGINE DETECTION MATRIX ({intel.virusTotal.positives} FLAGGED)</span>
          </div>
          <span className="text-xs font-mono text-slate-400">
            UPDATED: {new Date(intel.virusTotal.scanDate || Date.now()).toLocaleTimeString()}
          </span>
        </div>

        {intel.virusTotal.engineResults && Object.keys(intel.virusTotal.engineResults).length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {Object.entries(intel.virusTotal.engineResults).map(([engine, data]) => {
              const isMalicious = data.category === 'malicious';
              return (
                <div
                  key={engine}
                  className={`p-3 rounded-lg border font-mono text-xs transition-colors ${
                    isMalicious
                      ? 'bg-rose-950/40 border-rose-600/70 text-rose-300'
                      : 'bg-slate-900/60 border-slate-850 text-slate-400'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-slate-200 truncate">{engine}</span>
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
          <div className="text-center p-6 font-mono text-xs text-slate-500">
            No specific vendor breakdown available.
          </div>
        )}
      </div>
    </div>
  );
};
