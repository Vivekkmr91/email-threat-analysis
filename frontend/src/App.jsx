import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import AnalyzeEmail from './pages/AnalyzeEmail';
import AnalysisHistory from './pages/AnalysisHistory';
import ThreatGraph from './pages/ThreatGraph';
import Login from './pages/Login';
import { authAPI } from './utils/api';

function App() {
  const [session, setSession] = useState({ loading: true, user: null });
  const [loginError, setLoginError] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);

  useEffect(() => {
    let isMounted = true;
    authAPI
      .me()
      .then((data) => {
        if (isMounted) {
          setSession({ loading: false, user: data });
        }
      })
      .catch(() => {
        if (isMounted) {
          setSession({ loading: false, user: null });
        }
      });
    return () => {
      isMounted = false;
    };
  }, []);

  const handleLogin = async (username, password) => {
    setLoginLoading(true);
    setLoginError('');
    try {
      await authAPI.login({ username, password });
      const data = await authAPI.me();
      setSession({ loading: false, user: data });
    } catch (error) {
      setSession({ loading: false, user: null });
      setLoginError(error.message || 'Login failed');
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await authAPI.logout();
    } finally {
      setSession({ loading: false, user: null });
    }
  };

  if (session.loading) {
    return (
      <div style={{ display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ color: '#0f172a', fontSize: 16 }}>Loading session...</div>
      </div>
    );
  }

  if (!session.user) {
    return <Login onLogin={handleLogin} error={loginError} loading={loginLoading} />;
  }

  return (
    <Router>
      <div style={{ display: 'flex', minHeight: '100vh' }}>
        <Sidebar onLogout={handleLogout} username={session.user.username} />
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
