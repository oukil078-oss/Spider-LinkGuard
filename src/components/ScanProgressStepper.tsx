import React, { useEffect, useState } from 'react';
import { CheckCircle2, Loader2, Circle } from 'lucide-react';

interface ScanProgressStepperProps {
  isScanning: boolean;
}

const STEPS = [
  { id: 1, title: 'URL Analysis', detail: 'Defanging, homoglyphs & entropy' },
  { id: 2, title: 'Threat Intelligence', detail: 'URLhaus, VirusTotal & Google Safe Browsing' },
  { id: 3, title: 'Redirects', detail: 'HTTP redirect chain & evasion checks' },
  { id: 4, title: 'Sandbox Execution', detail: 'Headless DOM render & form inspection' },
  { id: 5, title: 'Risk Scoring', detail: 'Kaggle ML classifier & SIEM rules' },
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
    }, 700);

    return () => clearInterval(interval);
  }, [isScanning]);

  if (!isScanning) return null;

  return (
    <div className="bg-[#0f1422] border border-slate-800 rounded-2xl p-5 shadow-lg animate-in fade-in duration-300">
      <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <Loader2 className="w-4 h-4 text-sky-400 animate-spin" />
          <span className="text-sm font-medium text-slate-200">
            Analyzing target URL...
          </span>
        </div>
        <span className="text-xs text-slate-400 font-medium">
          Step {currentStep} of {STEPS.length}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
        {STEPS.map((step) => {
          const isDone = step.id < currentStep;
          const isCurrent = step.id === currentStep;

          return (
            <div
              key={step.id}
              className={`p-3 rounded-xl border transition-all ${
                isCurrent
                  ? 'bg-sky-950/30 border-sky-500/50'
                  : isDone
                  ? 'bg-slate-900/60 border-emerald-900/40'
                  : 'bg-slate-900/20 border-slate-800/50 opacity-50'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                {isDone ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                ) : isCurrent ? (
                  <Loader2 className="w-3.5 h-3.5 text-sky-400 animate-spin shrink-0" />
                ) : (
                  <Circle className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                )}
                <span
                  className={`text-xs font-medium truncate ${
                    isCurrent ? 'text-sky-300' : isDone ? 'text-emerald-300' : 'text-slate-400'
                  }`}
                >
                  {step.title}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">
                {step.detail}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
