import React, { useState } from 'react';
import { Menu, Shield, AlertTriangle, Globe } from 'lucide-react';
import { LandingPage } from './components/LandingPage';
import { Dashboard } from './components/Dashboard';

function App() {
  const [currentPage, setCurrentPage] = useState<'landing' | 'dashboard'>('landing');

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-950 to-blue-800">
      {currentPage === 'landing' ? (
        <LandingPage onGetStarted={() => setCurrentPage('dashboard')} />
      ) : (
        <Dashboard />
      )}
    </div>
  );
}

export default App;