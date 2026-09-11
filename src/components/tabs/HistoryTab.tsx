import React, { useState } from 'react';
import { History, RefreshCw, ExternalLink, Code2, Search } from 'lucide-react';
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
        return 'bg-rose-500/10 text-rose-400 border-rose-500/25';
      case 'MALICIOUS':
        return 'bg-red-500/10 text-red-400 border-red-500/25';
      case 'SUSPICIOUS':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/25';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25';
    }
  };

  return (
    <div className="space-y-6">
      {/* Scan History Table */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 mb-4 border-b border-slate-800/80">
          <div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <History className="w-4 h-4 text-sky-400" />
              Scan History ({history.length} Reports)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Cached investigation reports available for immediate retrieval
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
            {/* Search */}
            <div className="relative flex-1 sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by host, URL, or ID..."
                className="w-full bg-slate-900 border border-slate-750 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            {/* Verdict Filter */}
            <select
              value={filterVerdict}
              onChange={(e) => setFilterVerdict(e.target.value)}
              className="bg-slate-900 border border-slate-750 text-slate-200 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-sky-500 cursor-pointer"
            >
              <option value="ALL">All Verdicts</option>
              <option value="CRITICAL">Critical</option>
              <option value="MALICIOUS">Malicious</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="BENIGN">Clean / Safe</option>
            </select>

            <button
              onClick={onRefreshHistory}
              className="p-2 rounded-lg bg-slate-850 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-colors"
              title="Refresh list"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="text-center py-12 text-slate-400 text-xs">
            No scans match your search criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400 font-medium">
                <tr>
                  <th className="py-2.5 px-3">Report ID</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Target Hostname</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Password Fields</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filtered.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-3 font-mono text-sky-400 font-medium">{item.id}</td>
                    <td className="py-3 px-3 text-slate-400">
                      {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3 px-3 text-slate-200 font-medium truncate max-w-xs font-mono" title={item.hostname}>
                      {item.hostname}
                    </td>
                    <td className="py-3 px-3">
                      <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-semibold capitalize border ${getVerdictBadge(item.verdict)}`}>
                        {item.verdict}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-semibold text-slate-200">{item.overallScore}/100</td>
                    <td className="py-3 px-3">
                      {item.hasCredentialHarvester ? (
                        <span className="text-[11px] font-medium text-rose-400">Detected</span>
                      ) : (
                        <span className="text-[11px] text-slate-500">None</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => onSelectScan(item.id)}
                        className="px-3 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-sky-300 hover:text-white text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
                      >
                        View Report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* REST API Documentation */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center gap-2 pb-3 mb-3 border-b border-slate-800/80">
          <Code2 className="w-4 h-4 text-sky-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            REST API Integration Reference
          </h3>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed mb-4">
          Connect your security workflows, Slack bots, or SecOps workstations directly to Spider-LinkGuard using standard JSON endpoints.
        </p>

        <div className="space-y-3 text-xs">
          <div className="bg-slate-950 rounded-xl p-4 border border-slate-800/80">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 font-semibold text-[11px]">
                POST
              </span>
              <span className="text-slate-200 font-mono font-medium">/api/scan</span>
              <span className="text-slate-400">— Submit link for full sandbox inspection</span>
            </div>
            <pre className="text-slate-300 bg-[#080d18] p-3 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto">
{`curl -X POST https://spider-linkguard.vercel.app/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://example.com"}'`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
