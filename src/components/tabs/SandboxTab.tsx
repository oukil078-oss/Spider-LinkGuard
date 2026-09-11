import React, { useState } from 'react';
import { Eye, KeyRound, Radio, FileCode2, Maximize2, X, ExternalLink } from 'lucide-react';
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
        <div className="lg:col-span-7 bg-[#0b101b] border border-slate-800 rounded-xl p-4 flex flex-col">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <div className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-300">
              <Eye className="w-4 h-4 text-sky-400" />
              <span>HEADLESS CHROMIUM VIEWPORT CAPTURE</span>
            </div>
            {dom.screenshotBase64 && (
              <button
                onClick={() => setFullscreenScreenshot(true)}
                className="flex items-center gap-1 text-xs font-mono text-slate-400 hover:text-sky-400 cursor-pointer"
              >
                <Maximize2 className="w-3.5 h-3.5" />
                <span>EXPAND</span>
              </button>
            )}
          </div>

          <div className="relative flex-1 bg-slate-950 rounded-lg border border-slate-850 overflow-hidden flex items-center justify-center min-h-[360px] group">
            {dom.screenshotBase64 ? (
              <img
                src={dom.screenshotBase64}
                alt="Headless DOM Render"
                className="w-full h-full object-contain rounded cursor-pointer transition-transform duration-200 group-hover:scale-[1.01]"
                onClick={() => setFullscreenScreenshot(true)}
              />
            ) : (
              <div className="text-center p-6 text-slate-500 font-mono text-xs">
                No screenshot generated for this target.
              </div>
            )}
          </div>

          <div className="flex items-center justify-between mt-3 text-[11px] font-mono text-slate-400">
            <span>Viewport: 1280x800 Sandbox (No-Audio, No-Downloads)</span>
            <span>DOM Size: {dom.domSummary.bodyLength} bytes</span>
          </div>
        </div>

        {/* DOM Findings & Form Harvester Highlights (5 columns) */}
        <div className="lg:col-span-5 flex flex-col gap-4">
          {/* Credential Harvester Alert */}
          <div
            className={`rounded-xl border p-4 shadow-lg ${
              dom.hasCredentialHarvester
                ? 'bg-rose-950/30 border-rose-600/80 text-rose-300'
                : 'bg-slate-900/80 border-slate-800 text-slate-300'
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <KeyRound
                className={`w-5 h-5 ${
                  dom.hasCredentialHarvester ? 'text-rose-400 animate-pulse' : 'text-emerald-400'
                }`}
              />
              <span className="font-mono font-bold text-xs uppercase tracking-wider">
                {dom.hasCredentialHarvester
                  ? 'CREDENTIAL HARVESTER ALERT'
                  : 'CREDENTIAL FIELDS: NONE DETECTED'}
              </span>
            </div>
            <p className="text-xs font-sans text-slate-300 leading-relaxed mb-3">
              {dom.hasCredentialHarvester
                ? 'DOM parsing identified an active <input type="password"> field configured to capture authentication secrets.'
                : 'No input password fields were discovered in the top-level or iframe DOM hierarchy.'}
            </p>

            {dom.forms.map((form, idx) => (
              <div
                key={idx}
                className="bg-slate-950/80 rounded border border-slate-800 p-2.5 text-xs font-mono mb-2"
              >
                <div className="flex items-center justify-between text-slate-400 mb-1">
                  <span>
                    FORM #{idx + 1} ({form.method})
                  </span>
                  {form.hasPasswordInput && (
                    <span className="text-[10px] text-rose-400 font-bold bg-rose-950/60 px-1.5 py-0.5 rounded border border-rose-800">
                      PASSWORD FIELD
                    </span>
                  )}
                </div>
                <div className="text-sky-300 truncate" title={form.action}>
                  Action: {form.action}
                </div>
                <div className="text-slate-500 text-[11px] mt-1">
                  Inputs: {form.inputs.map((i) => `${i.name} [${i.type}]`).join(', ') || 'none'}
                </div>
              </div>
            ))}
          </div>

          {/* Page Metadata Summary */}
          <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-4 flex-1">
            <div className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-300 pb-2 mb-3 border-b border-slate-800">
              <FileCode2 className="w-4 h-4 text-sky-400" />
              <span>PAGE & DOM ATTRIBUTES</span>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[11px]">PAGE TITLE:</span>
                <span className="text-slate-200 font-semibold">{dom.title || 'Untitled'}</span>
              </div>

              <div>
                <span className="text-slate-500 block text-[11px]">EXTERNAL SCRIPTS LOADED:</span>
                <span className="text-slate-200">
                  {dom.scripts.filter((s) => s.isExternal).length} of {dom.scripts.length} total scripts
                </span>
              </div>

              <div>
                <span className="text-slate-500 block text-[11px]">IFRAMES COUNT:</span>
                <span className="text-slate-200">{dom.domSummary.iframesCount} embedded frames</span>
              </div>

              <div>
                <span className="text-slate-500 block text-[11px]">EVAL EXECUTION HOOKS:</span>
                <span className={dom.evalAttempts > 0 ? 'text-amber-400 font-bold' : 'text-emerald-400'}>
                  {dom.evalAttempts} eval() invocations intercepted
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Network Requests HAR Trace Table */}
      <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            <Radio className="w-4 h-4 text-sky-400" />
            <span>OUTBOUND NETWORK TELEMETRY (HAR REQUEST TRACE)</span>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {dom.networkRequests.length} REQUESTS CAPTURED
          </span>
        </div>

        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left font-mono text-xs">
            <thead className="sticky top-0 bg-[#0b101b] border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2.5 px-3">METHOD</th>
                <th className="py-2.5 px-3">STATUS</th>
                <th className="py-2.5 px-3">TYPE</th>
                <th className="py-2.5 px-3">DOMAIN / SCOPE</th>
                <th className="py-2.5 px-3">TARGET RESOURCE URL</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {dom.networkRequests.map((req, idx) => (
                <tr key={idx} className="hover:bg-slate-900/60 transition-colors">
                  <td className="py-2 px-3 font-bold text-slate-300">{req.method}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        req.status >= 200 && req.status < 300
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : req.status >= 300 && req.status < 400
                          ? 'bg-sky-500/20 text-sky-300'
                          : req.status >= 400
                          ? 'bg-rose-500/20 text-rose-300'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {req.status || 'PENDING'}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-400 uppercase text-[10px]">{req.type}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        req.external
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {req.external ? 'EXTERNAL' : 'ORIGIN'}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-300 truncate max-w-md" title={req.url}>
                    {req.url}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Fullscreen Screenshot Lightbox Modal */}
      {fullscreenScreenshot && dom.screenshotBase64 && (
        <div className="fixed inset-0 z-50 bg-black/90 flex flex-col items-center justify-center p-6 backdrop-blur-md">
          <div className="w-full max-w-6xl flex items-center justify-between pb-3 text-slate-300 font-mono text-xs">
            <span className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-sky-400" />
              FULL RESOLUTION SANDBOX VIEWPORT CAPTURE
            </span>
            <button
              onClick={() => setFullscreenScreenshot(false)}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-white cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="max-w-6xl max-h-[85vh] overflow-auto rounded-lg border border-slate-750 bg-slate-950 p-2">
            <img src={dom.screenshotBase64} alt="Full Viewport" className="w-full h-auto rounded" />
          </div>
        </div>
      )}
    </div>
  );
};
