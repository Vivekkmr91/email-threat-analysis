import React, { useState } from 'react';

export default function Login({ onLogin, error, loading }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!username || !password) {
      return;
    }
    await onLogin(username, password);
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #e2e8f0, #f8fafc)',
        padding: 24,
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 420,
          background: '#ffffff',
          borderRadius: 16,
          boxShadow: '0 20px 45px rgba(15, 23, 42, 0.1)',
          padding: '36px 32px',
        }}
      >
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#0f172a' }}>SOC Dashboard Login</div>
          <div style={{ fontSize: 13, color: '#64748b', marginTop: 6 }}>
            Sign in with the dashboard credentials configured in your .env file.
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'grid', gap: 16 }}>
          <label style={{ display: 'grid', gap: 6, fontSize: 13, color: '#0f172a' }}>
            Username
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="your-username"
              style={{
                padding: '10px 12px',
                borderRadius: 8,
                border: '1px solid #cbd5f5',
                fontSize: 14,
              }}
            />
          </label>

          <label style={{ display: 'grid', gap: 6, fontSize: 13, color: '#0f172a' }}>
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
              style={{
                padding: '10px 12px',
                borderRadius: 8,
                border: '1px solid #cbd5f5',
                fontSize: 14,
              }}
            />
          </label>

          {error && (
            <div
              style={{
                background: '#fee2e2',
                color: '#991b1b',
                padding: '10px 12px',
                borderRadius: 8,
                fontSize: 12,
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              background: '#2563eb',
              color: '#ffffff',
              border: 'none',
              padding: '12px 16px',
              borderRadius: 8,
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
