import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import AnalyzeEmail from './pages/AnalyzeEmail';
import AnalysisHistory from './pages/AnalysisHistory';
import ThreatGraph from './pages/ThreatGraph';

function App() {
  return (
    <Router>
      <div style={{ display: 'flex', minHeight: '100vh' }}>
        <Sidebar />
        <main style={{ marginLeft: 220, flex: 1, minHeight: '100vh', overflowY: 'auto' }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analyze" element={<AnalyzeEmail />} />
            <Route path="/analyses" element={<AnalysisHistory />} />
            <Route path="/graph" element={<ThreatGraph />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
