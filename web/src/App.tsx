import React, { useState, useEffect } from 'react';
import type { ViewType } from './types/api';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider } from './context/AuthContext';
import { Header } from './components/common/Header';
import { Footer } from './components/common/Footer';
import { SkipLink } from './components/common/SkipLink';
import { OperatorLoginModal } from './components/auth/OperatorLoginModal';
import { OverviewView } from './views/OverviewView';
import { RunsView } from './views/RunsView';
import { AuditLogView } from './views/AuditLogView';
import { BreakitView } from './views/BreakitView';
import { TimingView } from './views/TimingView';
import { ThreatModelView } from './views/ThreatModelView';
import { DataHandlingView } from './views/DataHandlingView';

const getViewFromHash = (): ViewType => {
  const hash = window.location.hash.replace('#', '').toLowerCase();
  const validViews: ViewType[] = [
    'overview',
    'runs',
    'audit',
    'breakit',
    'timing',
    'threat',
    'data-handling',
  ];
  if (validViews.includes(hash as ViewType)) {
    return hash as ViewType;
  }
  return 'overview';
};

export const AppContent: React.FC = () => {
  const [currentView, setCurrentView] = useState<ViewType>(getViewFromHash());
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);

  useEffect(() => {
    const handleHashChange = () => {
      setCurrentView(getViewFromHash());
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleNavigate = (view: ViewType, runId?: string) => {
    setCurrentView(view);
    window.location.hash = view;
    if (runId) {
      setSelectedRunId(runId);
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
        backgroundColor: 'var(--color-bg-base)',
        color: 'var(--color-text-primary)',
      }}
    >
      <SkipLink targetId="main-content" />

      <Header
        currentView={currentView}
        onNavigate={handleNavigate}
        onOpenLogin={() => setIsLoginModalOpen(true)}
      />

      <main
        id="main-content"
        tabIndex={-1}
        style={{
          maxWidth: '1440px',
          width: '100%',
          margin: '0 auto',
          padding: 'var(--space-8) var(--space-6)',
          flex: 1,
          outline: 'none',
        }}
      >
        {currentView === 'overview' && <OverviewView onNavigate={handleNavigate} />}
        {currentView === 'runs' && (
          <RunsView
            selectedRunId={selectedRunId}
            onSelectRun={setSelectedRunId}
            onNavigate={handleNavigate}
          />
        )}
        {currentView === 'audit' && <AuditLogView onNavigate={handleNavigate} />}
        {currentView === 'breakit' && <BreakitView onNavigate={handleNavigate} />}
        {currentView === 'timing' && <TimingView onNavigate={handleNavigate} />}
        {currentView === 'threat' && <ThreatModelView onNavigate={handleNavigate} />}
        {currentView === 'data-handling' && <DataHandlingView onNavigate={handleNavigate} />}
      </main>

      <Footer currentView={currentView} onNavigate={handleNavigate} />

      <OperatorLoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
      />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
};

export default App;
