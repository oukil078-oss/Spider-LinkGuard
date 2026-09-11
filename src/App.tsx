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
  Shield,
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
      setErrorMessage(err.message || 'Security scanner encountered an error');
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
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'sandbox', label: 'Page Preview & DOM', icon: Eye },
    { id: 'redirects', label: 'Redirect Chain', icon: GitCommit },
    { id: 'threatintel', label: 'Threat Intelligence', icon: ShieldAlert },
    { id: 'heuristics', label: 'Heuristics & Homoglyphs', icon: Binary },
    { id: 'rules', label: 'Detection Rules', icon: FileCode2 },
    { id: 'history', label: 'History', icon: History },
  ];

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-200 flex flex-col font-sans selection:bg-sky-500/20 selection:text-sky-300">
      {/* Header */}
      <Header
        onOpenSettings={() => setSettingsOpen(true)}
        cachedScansCount={scanHistory.length}
      />

      {/* Main Workspace Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 space-y-6">
        {/* Omnibar Input */}
        <DetonationOmnibar onScan={handleScan} isScanning={isScanning} />

        {/* Real-time Scan Progress */}
        <ScanProgressStepper isScanning={isScanning} />

        {/* Error Alert */}
        {errorMessage && (
          <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/60 text-rose-300 flex items-start gap-3 text-sm">
            <AlertCircle className="w-5 h-5 shrink-0 mt-0.5 text-rose-400" />
            <div>
              <span className="font-semibold">Scan Error:</span> {errorMessage}
            </div>
          </div>
        )}

        {/* Scan Results View */}
        {currentReport && !isScanning && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Verdict Banner */}
            <VerdictBanner report={currentReport} />

            {/* Tab Navigation Bar */}
            <div className="flex items-center gap-1.5 p-1 bg-[#0f1422] rounded-xl border border-slate-800/80 overflow-x-auto">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;

                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all whitespace-nowrap cursor-pointer ${
                      isActive
                        ? 'bg-slate-800 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                    }`}
                  >
                    <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
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

        {/* Initial Empty State */}
        {!currentReport && !isScanning && (
          <div className="bg-[#0f1422] border border-slate-800/80 rounded-2xl p-12 text-center shadow-lg space-y-4 max-w-3xl mx-auto">
            <div className="inline-flex p-3.5 rounded-2xl bg-sky-500/10 border border-sky-500/20 text-sky-400">
              <Shield className="w-8 h-8" />
            </div>
            <h3 className="text-lg font-semibold text-slate-100 tracking-tight">
              Ready to analyze a suspicious link
            </h3>
            <p className="text-sm text-slate-400 max-w-lg mx-auto leading-relaxed">
              Submit any URL, short link, or defanged indicator above to evaluate it with our machine learning classifier, threat reputation engines, and DOM sandbox.
            </p>
            <div className="flex flex-wrap justify-center gap-3 pt-2">
              <button
                onClick={() =>
                  handleScan(
                    'http://paypal-verification-account-sec.top/login.php'
                  )
                }
                className="px-4 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-medium text-sky-300 hover:text-white transition-colors cursor-pointer"
              >
                Try Phishing Sample
              </button>
              <button
                onClick={() =>
                  handleScan(
                    'https://en.wikipedia.org/wiki/Computer_security'
                  )
                }
                className="px-4 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-medium text-slate-300 hover:text-white transition-colors cursor-pointer"
              >
                Try Safe Domain
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#0a0f1d] py-5 px-6 text-xs text-slate-500 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <span className="text-slate-400">Spider-LinkGuard — Automated URL Threat Intelligence & Sandbox Platform</span>
          <span className="text-slate-500">Standalone cybersecurity research microservice</span>
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
