import React, { useState } from 'react';
import { Eye, KeyRound, Radio, FileCode2, Maximize2, X, ShieldAlert, ShieldCheck } from 'lucide-react';
import { ScanReport } from '../../types.ts';

interface SandboxTabProps {
  report: ScanReport;
}

export const SandboxTab: React.FC<SandboxTabProps> = ({ report }) => {
  const [fullscreenScreenshot, setFullscreenScreenshot] = useState(false);
  const dom = report.domSandbox;

  return (
    <div className="space-y-6">
      {/* Visual Rendered Screenshot & DOM Highlights */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Screenshot Viewer (7 columns) */}
        <div className="lg:col-span-7 bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 flex flex-col shadow-sm">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Eye className="w-4 h-4 text-sky-400" />
              <span>Isolated Browser Render</span>
            </div>
            {dom.screenshotBase64 && (
              <button
                onClick={() => setFullscreenScreenshot(true)}
                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-sky-400 cursor-pointer font-medium"
              >
                <Maximize2 className="w-3.5 h-3.5" />
                <span>Expand</span>
              </button>
            )}
          </div>

          <div className="relative flex-1 bg-slate-950 rounded-xl border border-slate-800/80 overflow-hidden flex items-center justify-center min-h-[360px] group">
            {dom.screenshotBase64 ? (
              <img
                src={dom.screenshotBase64}
                alt="Headless DOM Render"
                className="w-full h-full object-contain rounded-xl cursor-pointer transition-transform duration-200 group-hover:scale-[1.01]"
                onClick={() => setFullscreenScreenshot(true)}
              />
            ) : (
              <div className="text-center p-6 text-slate-500 text-xs">
                No screenshot generated for this target.
              </div>
            )}
          </div>

          <div className="flex items-center justify-between mt-3 text-xs text-slate-400">
            <span>Viewport: 1280x800 Sandbox (No Audio / No Downloads)</span>
            <span>DOM Size: {dom.domSummary.bodyLength} bytes</span>
          </div>
        </div>

        {/* DOM Findings & Form Harvester Highlights (5 columns) */}
        <div className="lg:col-span-5 flex flex-col gap-4">
          {/* Credential Harvester Alert */}
          <div
            className={`rounded-2xl border p-5 shadow-sm ${
              dom.hasCredentialHarvester
                ? 'bg-rose-950/20 border-rose-800/40 text-rose-200'
                : 'bg-[#0f1422] border-slate-800/80 text-slate-200'
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <KeyRound
                className={`w-5 h-5 ${
                  dom.hasCredentialHarvester ? 'text-rose-400' : 'text-emerald-400'
                }`}
              />
              <span className="font-semibold text-sm">
                {dom.hasCredentialHarvester
                  ? 'Credential Harvesting Form Detected'
                  : 'No Password Fields Discovered'}
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-3">
              {dom.hasCredentialHarvester
                ? 'DOM parsing identified an active password input field configured to capture sensitive authentication secrets.'
                : 'No password input fields were discovered in the top-level or iframe DOM hierarchy.'}
            </p>

            {dom.forms.map((form, idx) => (
              <div
                key={idx}
                className="bg-slate-900/80 rounded-xl border border-slate-800 p-3 text-xs mb-2"
              >
                <div className="flex items-center justify-between text-slate-300 mb-1">
                  <span className="font-medium">
                    Form #{idx + 1} ({form.method.toUpperCase()})
                  </span>
                  {form.hasPasswordInput && (
                    <span className="text-[10px] text-rose-400 font-semibold bg-rose-500/10 px-2 py-0.5 rounded-full border border-rose-500/25">
                      Password Field
                    </span>
                  )}
                </div>
                <div className="text-sky-300 font-mono text-xs truncate" title={form.action}>
                  Action: {form.action || '#'}
                </div>
                <div className="text-slate-400 text-xs mt-1">
                  Inputs: {form.inputs.map((i) => `${i.name || 'unnamed'} (${i.type})`).join(', ') || 'none'}
                </div>
              </div>
            ))}
          </div>

          {/* Page Metadata Summary */}
          <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-5 flex-1 shadow-sm">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100 pb-2 mb-3 border-b border-slate-800/80">
              <FileCode2 className="w-4 h-4 text-sky-400" />
              <span>Page & Script Attributes</span>
            </div>

            <div className="space-y-2.5 text-xs">
              <div>
                <span className="text-slate-400 block text-xs">Page Title:</span>
                <span className="text-slate-200 font-medium">{dom.title || 'Untitled'}</span>
              </div>

              <div>
                <span className="text-slate-400 block text-xs">External Scripts:</span>
                <span className="text-slate-200">
                  {dom.scripts.filter((s) => s.isExternal).length} of {dom.scripts.length} total scripts
                </span>
              </div>

              <div>
                <span className="text-slate-400 block text-xs">Embedded iFrames:</span>
                <span className="text-slate-200">{dom.domSummary.iframesCount} frames found</span>
              </div>

              <div>
                <span className="text-slate-400 block text-xs">Dynamic eval() Interceptions:</span>
                <span className={dom.evalAttempts > 0 ? 'text-amber-400 font-semibold' : 'text-slate-300'}>
                  {dom.evalAttempts} eval() invocations intercepted
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Network Requests HAR Trace Table */}
      <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Radio className="w-4 h-4 text-sky-400" />
            <span>Network Requests Captured ({dom.networkRequests.length})</span>
          </div>
          <span className="text-xs text-slate-400">
            Live Sandbox Telemetry
          </span>
        </div>

        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-[#0f1422] border-b border-slate-800 text-slate-400 font-medium">
              <tr>
                <th className="py-2.5 px-3">Method</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Scope</th>
                <th className="py-2.5 px-3">Target Resource URL</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {dom.networkRequests.map((req, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                  <td className="py-2 px-3 font-semibold text-slate-200 font-mono">{req.method}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                        req.status >= 200 && req.status < 300
                          ? 'bg-emerald-500/10 text-emerald-400'
                          : req.status >= 300 && req.status < 400
                          ? 'bg-sky-500/10 text-sky-400'
                          : req.status >= 400
                          ? 'bg-rose-500/10 text-rose-400'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {req.status || 'Pending'}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-400 text-xs">{req.type}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                        req.external
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/25'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {req.external ? 'External' : 'Origin'}
                    </span>
                  </td>
                  <td className="py-2 px-3 font-mono text-slate-300 truncate max-w-md text-xs" title={req.url}>
                    {req.url}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Fullscreen Screenshot Modal */}
      {fullscreenScreenshot && dom.screenshotBase64 && (
        <div className="fixed inset-0 z-50 bg-black/85 flex flex-col items-center justify-center p-6 backdrop-blur-sm">
          <div className="w-full max-w-6xl flex items-center justify-between pb-3 text-slate-300 text-sm font-medium">
            <span className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-sky-400" />
              Full Viewport Render
            </span>
            <button
              onClick={() => setFullscreenScreenshot(false)}
              className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-white cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="max-w-6xl max-h-[85vh] overflow-auto rounded-2xl border border-slate-750 bg-slate-950 p-3">
            <img src={dom.screenshotBase64} alt="Full Viewport" className="w-full h-auto rounded-xl" />
          </div>
        </div>
      )}
    </div>
  );
};
