import React from 'react';
import { NavLink } from 'react-router-dom';

const navItems = [
  { path: '/', icon: '📊', label: 'Dashboard' },
  { path: '/analyze', icon: '🔍', label: 'Analyze Email' },
  { path: '/analyses', icon: '📋', label: 'Analysis History' },
  { path: '/graph', icon: '🕸️', label: 'Threat Graph' },
];

export default function Sidebar() {
  return (
    <aside style={{
      width: 220,
      background: '#0f172a',
      borderRight: '1px solid #1e293b',
      display: 'flex',
      flexDirection: 'column',
      position: 'fixed',
      top: 0, left: 0, bottom: 0,
      zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{ padding: '20px 16px', borderBottom: '1px solid #1e293b' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
            borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 18,
          }}>🛡️</div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 13, color: '#f1f5f9' }}>Email Threat</div>
            <div style={{ fontSize: 11, color: '#64748b' }}>Analysis System</div>
          </div>
        </div>
      </div>

      {/* Nav Items */}
      <nav style={{ padding: '12px 8px', flex: 1 }}>
        {navItems.map(item => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '10px 12px',
              borderRadius: 8,
              textDecoration: 'none',
              marginBottom: 4,
              fontSize: 14,
              fontWeight: isActive ? 600 : 400,
              background: isActive ? '#1e293b' : 'transparent',
              color: isActive ? '#f1f5f9' : '#94a3b8',
              transition: 'all 0.15s',
            })}
          >
            <span style={{ fontSize: 16 }}>{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div style={{ padding: '12px 16px', borderTop: '1px solid #1e293b', fontSize: 11, color: '#475569' }}>
        <div>Multi-Agent AI</div>
        <div style={{ marginTop: 2 }}>LangGraph + Neo4j</div>
      </div>
    </aside>
  );
}
