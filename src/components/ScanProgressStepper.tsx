import React, { useEffect, useState } from 'react';
import { CheckCircle2, Loader2, CircleDot } from 'lucide-react';

interface ScanProgressStepperProps {
  isScanning: boolean;
}

const STEPS = [
  { id: 1, title: 'URL Normalizer', detail: 'De-fanging, Homoglyph check, Shannon entropy' },
  { id: 2, title: 'Threat Intelligence', detail: 'URLhaus, VirusTotal, urlscan, GSB ingestion' },
  { id: 3, title: 'Redirect Traversal', detail: 'HTTP 3xx chain, Meta-Refresh, Evasion analysis' },
  { id: 4, title: 'DOM Sandbox', detail: 'Headless Chromium, Credential harvester & HAR' },
  { id: 5, title: 'Scoring Matrix', detail: 'Weighted 0-100 risk score & SIEM rules' },
];

export const ScanProgressStepper: React.FC<ScanProgressStepperProps> = ({ isScanning }) => {
  const [currentStep, setCurrentStep] = useState<number>(1);

  useEffect(() => {
    if (!isScanning) {
      setCurrentStep(1);
      return;
    }

    const interval = setInterval(() => {
      setCurrentStep((prev) => (prev < 5 ? prev + 1 : prev));
    }, 750);

    return () => clearInterval(interval);
  }, [isScanning]);

  if (!isScanning) return null;

  return (
    <div className="bg-[#0b101b] border border-sky-900/50 rounded-xl p-5 shadow-2xl animate-in fade-in duration-300">
      <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Loader2 className="w-4 h-4 text-sky-400 animate-spin" />
          <span className="text-xs font-mono font-bold text-sky-300 uppercase tracking-wider">
            DETONATION ENGINE RUNNING • ACTIVE PIPELINE
          </span>
        </div>
        <span className="text-xs font-mono text-slate-400">
          STAGE {currentStep} OF {STEPS.length}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {STEPS.map((step) => {
          const isDone = step.id < currentStep;
          const isCurrent = step.id === currentStep;

          return (
            <div
              key={step.id}
              className={`p-3 rounded-lg border transition-all ${
                isCurrent
                  ? 'bg-sky-950/40 border-sky-500/70 shadow-lg shadow-sky-500/10'
                  : isDone
                  ? 'bg-slate-900/90 border-emerald-800/40'
                  : 'bg-slate-900/30 border-slate-850 opacity-60'
              }`}
            >
              <div className="flex items-center gap-2 mb-1.5">
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 text-sky-400 animate-spin shrink-0" />
                ) : (
                  <CircleDot className="w-4 h-4 text-slate-600 shrink-0" />
                )}
                <span
                  className={`text-xs font-mono font-bold truncate ${
                    isCurrent ? 'text-sky-300' : isDone ? 'text-emerald-300' : 'text-slate-400'
                  }`}
                >
                  {step.title}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-sans leading-relaxed line-clamp-2">
                {step.detail}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
