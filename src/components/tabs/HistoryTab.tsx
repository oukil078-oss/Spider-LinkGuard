import React, { useState } from 'react';
import { History, RefreshCw, ExternalLink, Code2, Terminal, Search } from 'lucide-react';
import { ScanHistorySummary, ScanVerdict } from '../../types.ts';

interface HistoryTabProps {
  history: ScanHistorySummary[];
  onSelectScan: (id: string) => void;
  onRefreshHistory: () => void;
}

export const HistoryTab: React.FC<HistoryTabProps> = ({
  history,
  onSelectScan,
  onRefreshHistory,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<string>('ALL');

  const filtered = history.filter((item) => {
    const matchesSearch =
      item.inputUrl.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.id.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesVerdict = filterVerdict === 'ALL' || item.verdict === filterVerdict;

    return matchesSearch && matchesVerdict;
  });

  const getVerdictBadge = (v: ScanVerdict) => {
    switch (v) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'MALICIOUS':
        return 'bg-red-500/20 text-red-300 border-red-500/40';
      case 'SUSPICIOUS':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      default:
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    }
  };

  return (
    <div className="space-y-6">
      {/* Scan History Table */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-sky-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              CACHED DETONATION HISTORY ({history.length} DOSSIERS)
            </h3>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            {/* Search */}
            <div className="relative flex-1 sm:w-60">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Filter by host, URL, ID..."
                className="w-full bg-slate-950 border border-slate-800 rounded px-8 py-1 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            {/* Verdict Filter */}
            <select
              value={filterVerdict}
              onChange={(e) => setFilterVerdict(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs font-mono text-slate-300 focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Verdicts</option>
              <option value="CRITICAL">Critical</option>
              <option value="MALICIOUS">Malicious</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="BENIGN">Benign</option>
            </select>

            <button
              onClick={onRefreshHistory}
              className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
              title="Refresh history"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="text-center py-10 text-slate-500 font-mono text-xs">
            No scan history matching current criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2.5 px-3">SCAN ID</th>
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">TARGET HOSTNAME</th>
                  <th className="py-2.5 px-3">VERDICT</th>
                  <th className="py-2.5 px-3">SCORE</th>
                  <th className="py-2.5 px-3">DOM HARVEST</th>
                  <th className="py-2.5 px-3">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {filtered.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-900/60 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-sky-400">{item.id}</td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 text-slate-200 font-bold truncate max-w-xs" title={item.hostname}>
                      {item.hostname}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getVerdictBadge(
                          item.verdict
                        )}`}
                      >
                        {item.verdict}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-bold text-slate-200">{item.overallScore}/100</td>
                    <td className="py-2.5 px-3">
                      {item.hasCredentialHarvester ? (
                        <span className="text-[10px] font-bold text-rose-400">PW HARVESTER</span>
                      ) : (
                        <span className="text-[10px] text-slate-500">None</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => onSelectScan(item.id)}
                        className="px-2 py-1 rounded bg-slate-900 hover:bg-sky-950 border border-slate-750 hover:border-sky-600 text-sky-400 text-xs font-mono transition-colors cursor-pointer"
                      >
                        VIEW REPORT
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* REST API Integration & Pivot Documentation for Zak's Spider */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center gap-2 pb-3 mb-3 border-b border-slate-800">
          <Code2 className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
            ZAK'S SPIDER SECOPS INTEGRATION API (REST PIVOT GUIDE)
          </h3>
        </div>

        <p className="text-xs font-sans text-slate-300 leading-relaxed mb-4">
          Zak's Spider SecOps Workstation pivots URLs into Spider-LinkGuard via standard REST endpoints.
          This microservice returns fully evaluated JSON reports, threat scores, and SIEM rules.
        </p>

        <div className="space-y-4 text-xs font-mono">
          {/* POST /api/scan */}
          <div className="bg-slate-950 rounded-lg p-4 border border-slate-850">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold">
                POST
              </span>
              <span className="text-slate-200 font-bold">/api/scan</span>
              <span className="text-slate-500">— Detonate URL and return full dossier</span>
            </div>
            <pre className="text-slate-300 bg-[#070b13] p-3 rounded border border-slate-800 mt-2 overflow-x-auto">
{`curl -X POST http://localhost:3001/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "hxxps://login-microsoft365[.]security-update[.]xyz/auth",
    "options": {
      "userAgent": "Mozilla/5.0...",
      "followRedirects": true
    }
  }'`}
            </pre>
          </div>

          {/* GET /api/scan/:id */}
          <div className="bg-slate-950 rounded-lg p-4 border border-slate-850">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/40 font-bold">
                GET
              </span>
              <span className="text-slate-200 font-bold">/api/scan/:id</span>
              <span className="text-slate-500">— Retrieve cached report</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
