import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { emailAPI } from '../utils/api';
import VerdictBadge from '../components/VerdictBadge';
import { formatDate, formatScore } from '../utils/helpers';

const verdictOptions = ['', 'malicious', 'suspicious', 'spam', 'clean', 'unknown'];

export default function AnalysisHistory() {
  const [analyses, setAnalyses] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [verdict, setVerdict] = useState('');
  const [selected, setSelected] = useState(null);
  const navigate = useNavigate();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await emailAPI.listAnalyses({
        page, page_size: 20,
        verdict: verdict || undefined,
        search: search || undefined,
      });
      setAnalyses(data.items);
      setTotal(data.total);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [page, verdict, search]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [verdict, search]);

  const totalPages = Math.ceil(total / 20);

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9' }}>Analysis History</h1>
          <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>{total} total analyses</p>
        </div>
        <button onClick={() => navigate('/analyze')} style={{
          padding: '8px 16px', background: '#3b82f6', border: 'none', borderRadius: 8,
          color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer',
        }}>+ Analyze New</button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search by sender or subject..."
          style={{
            flex: 1, background: '#1e293b', border: '1px solid #334155', color: '#f1f5f9',
            padding: '8px 12px', borderRadius: 8, fontSize: 13, outline: 'none',
          }}
        />
        <select
          value={verdict}
          onChange={e => setVerdict(e.target.value)}
          style={{
            background: '#1e293b', border: '1px solid #334155', color: '#94a3b8',
            padding: '8px 12px', borderRadius: 8, fontSize: 13, cursor: 'pointer',
          }}
        >
          {verdictOptions.map(v => (
            <option key={v} value={v}>{v ? v.charAt(0).toUpperCase() + v.slice(1) : 'All Verdicts'}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 12, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#0f172a' }}>
              {['Date', 'From', 'Subject', 'Verdict', 'Score', 'Categories', ''].map(h => (
                <th key={h} style={{
                  padding: '12px 16px', textAlign: 'left', fontSize: 12,
                  color: '#64748b', fontWeight: 600, letterSpacing: '0.05em',
                  borderBottom: '1px solid #334155',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
                  Loading analyses...
                </td>
              </tr>
            ) : analyses.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: 40, textAlign: 'center', color: '#475569' }}>
                  No analyses found. <a href="/analyze" style={{ color: '#3b82f6' }}>Analyze an email</a>
                </td>
              </tr>
            ) : analyses.map((a) => (
              <tr
                key={a.analysis_id}
                onClick={() => setSelected(selected?.analysis_id === a.analysis_id ? null : a)}
                style={{
                  borderBottom: '1px solid #1e293b',
                  cursor: 'pointer',
                  background: selected?.analysis_id === a.analysis_id ? '#0f172a' : 'transparent',
                  transition: 'background 0.1s',
                }}
              >
                <td style={tdStyle}>{formatDate(a.created_at)}</td>
                <td style={tdStyle}>
                  <span style={{ color: '#94a3b8', fontSize: 12 }}>
                    {a.sender_email ? (a.sender_email.length > 25 ? a.sender_email.substring(0, 25) + '…' : a.sender_email) : '—'}
                  </span>
                </td>
                <td style={tdStyle}>
                  <span style={{ color: '#e2e8f0' }}>
                    {a.subject ? (a.subject.length > 35 ? a.subject.substring(0, 35) + '…' : a.subject) : '—'}
                  </span>
                </td>
                <td style={tdStyle}>
                  <VerdictBadge verdict={a.verdict} size="sm" />
                </td>
                <td style={{ ...tdStyle, color: '#f1f5f9', fontWeight: 600 }}>
                  {formatScore(a.threat_score)}
                </td>
                <td style={tdStyle}>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {(a.threat_categories || []).slice(0, 2).map((cat, i) => (
                      <span key={i} style={{
                        fontSize: 10, padding: '1px 6px', borderRadius: 8,
                        background: '#0f172a', color: '#94a3b8', border: '1px solid #334155',
                      }}>{cat.replace(/_/g, ' ')}</span>
                    ))}
                  </div>
                </td>
                <td style={tdStyle}>
                  {a.has_feedback && <span style={{ color: '#22c55e', fontSize: 11 }}>✓ Reviewed</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            style={pageBtn(page !== 1)}
          >← Previous</button>
          <span style={{ padding: '6px 12px', color: '#94a3b8', fontSize: 13 }}>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            style={pageBtn(page !== totalPages)}
          >Next →</button>
        </div>
      )}
    </div>
  );
}

const tdStyle = { padding: '12px 16px', fontSize: 13 };
const pageBtn = (active) => ({
  padding: '6px 14px', background: '#1e293b', border: '1px solid #334155',
  color: active ? '#3b82f6' : '#475569', borderRadius: 6, cursor: active ? 'pointer' : 'not-allowed',
  fontSize: 13,
});
