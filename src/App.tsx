import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  Eye,
  GitCommit,
  ShieldAlert,
  Binary,
  FileCode2,
  History,
  AlertCircle,
  Terminal,
} from 'lucide-react';
import { Header } from './components/Header.tsx';
import { DetonationOmnibar } from './components/DetonationOmnibar.tsx';
import { ScanProgressStepper } from './components/ScanProgressStepper.tsx';
import { VerdictBanner } from './components/VerdictBanner.tsx';
import { OverviewTab } from './components/tabs/OverviewTab.tsx';
import { SandboxTab } from './components/tabs/SandboxTab.tsx';
import { RedirectTab } from './components/tabs/RedirectTab.tsx';
import { ThreatIntelTab } from './components/tabs/ThreatIntelTab.tsx';
import { HeuristicsTab } from './components/tabs/HeuristicsTab.tsx';
import { RulesAndExportTab } from './components/tabs/RulesAndExportTab.tsx';
import { HistoryTab } from './components/tabs/HistoryTab.tsx';
import { SettingsModal } from './components/SettingsModal.tsx';
import { ScanReport, ScanHistorySummary } from './types.ts';

export function App() {
  const [currentReport, setCurrentReport] = useState<ScanReport | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanHistory, setScanHistory] = useState<ScanHistorySummary[]>([]);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [settingsOpen, setSettingsOpen] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Fetch scan history and cached count
  const refreshHistory = async () => {
    try {
      const res = await fetch('/api/scans');
      if (res.ok) {
        const data = await res.json();
        setScanHistory(data);
      }
    } catch {
      // Backend might be warming up
    }
  };

  useEffect(() => {
    refreshHistory();
  }, []);

  const handleScan = async (url: string, userAgent?: string) => {
    setIsScanning(true);
    setErrorMessage(null);

    const vtKey = localStorage.getItem('spider_vt_key') || undefined;
    const urlscanKey = localStorage.getItem('spider_urlscan_key') || undefined;
    const gsbKey = localStorage.getItem('spider_gsb_key') || undefined;

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          options: {
            userAgent,
            apiKeys: {
              virusTotal: vtKey,
              urlscan: urlscanKey,
              googleSafeBrowsing: gsbKey,
            },
          },
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `Scan failed with status ${res.status}`);
      }

      const report: ScanReport = await res.json();
      setCurrentReport(report);
      setActiveTab('overview');
      refreshHistory();
    } catch (err: any) {
      setErrorMessage(err.message || 'Detonation engine encountered an error');
    } finally {
      setIsScanning(false);
    }
  };

  const loadScanById = async (id: string) => {
    try {
      const res = await fetch(`/api/scan/${id}`);
      if (res.ok) {
        const report = await res.json();
        setCurrentReport(report);
        setActiveTab('overview');
      }
    } catch {
      setErrorMessage(`Failed to retrieve scan report '${id}'`);
    }
  };

  const tabs = [
    { id: 'overview', label: 'OVERVIEW', icon: LayoutDashboard },
    { id: 'sandbox', label: 'DOM SANDBOX & SCREENSHOT', icon: Eye },
    { id: 'redirects', label: 'REDIRECT CHAIN', icon: GitCommit },
    { id: 'threatintel', label: 'THREAT INTEL', icon: ShieldAlert },
    { id: 'heuristics', label: 'ENTROPY & HOMOGLYPHS', icon: Binary },
    { id: 'rules', label: 'SIEM & IDS RULES', icon: FileCode2 },
    { id: 'history', label: 'HISTORY & API', icon: History },
  ];

  return (
    <div className="min-h-screen bg-[#070b13] text-slate-200 flex flex-col font-sans selection:bg-sky-500/20 selection:text-sky-300">
      {/* Header */}
      <Header
        onOpenSettings={() => setSettingsOpen(true)}
        cachedScansCount={scanHistory.length}
      />

      {/* Main Workspace Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Omnibar Input */}
        <DetonationOmnibar onScan={handleScan} isScanning={isScanning} />

        {/* Real-time Detonation Pipeline Progress */}
        <ScanProgressStepper isScanning={isScanning} />

        {/* Error Alert */}
        {errorMessage && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-600/80 text-rose-300 flex items-start gap-3 text-xs font-mono">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
            <div>
              <span className="font-bold">DETONATION FAILED:</span> {errorMessage}
            </div>
          </div>
        )}

        {/* Scan Results View */}
        {currentReport && !isScanning && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Verdict Banner */}
            <VerdictBanner report={currentReport} />

            {/* Tab Navigation Strip */}
            <div className="flex items-center gap-1.5 border-b border-slate-800 overflow-x-auto pb-1">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;

                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-2 px-3.5 py-2.5 rounded-t-lg font-mono text-xs font-bold transition-all whitespace-nowrap cursor-pointer ${
                      isActive
                        ? 'bg-[#0b101b] text-sky-400 border-t-2 border-t-sky-400 border-x border-slate-800'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
                    }`}
                  >
                    <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-sky-400' : 'text-slate-500'}`} />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

            {/* Tab Body */}
            <div>
              {activeTab === 'overview' && <OverviewTab report={currentReport} />}
              {activeTab === 'sandbox' && <SandboxTab report={currentReport} />}
              {activeTab === 'redirects' && <RedirectTab report={currentReport} />}
              {activeTab === 'threatintel' && <ThreatIntelTab report={currentReport} />}
              {activeTab === 'heuristics' && <HeuristicsTab report={currentReport} />}
              {activeTab === 'rules' && <RulesAndExportTab report={currentReport} />}
              {activeTab === 'history' && (
                <HistoryTab
                  history={scanHistory}
                  onSelectScan={loadScanById}
                  onRefreshHistory={refreshHistory}
                />
              )}
            </div>
          </div>
        )}

        {/* Initial Empty State (When no scan performed yet) */}
        {!currentReport && !isScanning && (
          <div className="bg-[#0b101b] border border-slate-800 rounded-xl p-10 text-center shadow-xl space-y-4">
            <div className="inline-flex p-4 rounded-2xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
              <ShieldAlert className="w-10 h-10" />
            </div>
            <h2 className="text-lg font-mono font-bold text-slate-100 uppercase tracking-wide">
              STANDALONE SANDBOX READY FOR DETONATION
            </h2>
            <p className="text-xs font-sans text-slate-400 max-w-xl mx-auto leading-relaxed">
              Paste any suspicious link, URL shortener, credential phishing form, or defanged IOC in the
              omnibar above. Alternatively, select one of the attack presets to simulate an active threat
              detonation.
            </p>
            <div className="flex flex-wrap justify-center gap-3 pt-2">
              <button
                onClick={() =>
                  handleScan(
                    'hxxps://login-microsoft365[.]security-update-token[.]xyz/auth/verify?session=live'
                  )
                }
                className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-750 text-xs font-mono text-sky-400 hover:text-sky-300 transition-colors cursor-pointer"
              >
                RUN SAMPLE M365 PHISHING DETONATION
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#0b101b] py-4 px-6 text-center text-xs font-mono text-slate-500 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>SPIDER-LINKGUARD v1.0.0 • AUTONOMOUS MALWARE DETONATION PLATFORM</span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <Terminal className="w-3.5 h-3.5 text-sky-400" />
            COMPANION TO ZAK'S SPIDER SECOPS WORKSTATION
          </span>
        </div>
      </footer>

      {/* Settings Modal */}
      <SettingsModal
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        onSave={() => {}}
      />
    </div>
  );
}

export default App;
