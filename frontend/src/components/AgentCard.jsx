import React, { useState } from 'react';
import { scoreToColor, formatScore, agentLabels } from '../utils/helpers';

export default function AgentCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const score = finding.score || 0;
  const color = scoreToColor(score);
  const label = agentLabels[finding.agent_name] || finding.agent_name;

  return (
    <div style={{
      background: '#1e293b',
      border: `1px solid ${color}40`,
      borderRadius: 12,
      padding: '16px',
      transition: 'all 0.2s',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{label}</div>
          <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
            Confidence: {formatScore(finding.confidence || 0)}
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: 22, fontWeight: 700, color }}>
            {formatScore(score)}
          </div>
          <div style={{
            width: 60, height: 4, background: '#0f172a', borderRadius: 2, marginTop: 4,
          }}>
            <div style={{
              width: `${score * 100}%`, height: '100%',
              background: color, borderRadius: 2,
              transition: 'width 1s ease',
            }} />
          </div>
        </div>
      </div>

      {finding.categories && finding.categories.length > 0 && (
        <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {finding.categories.map((cat, i) => (
            <span key={i} style={{
              fontSize: 10, padding: '2px 8px', borderRadius: 10,
              background: '#0f172a', color: '#94a3b8', border: '1px solid #334155',
            }}>{cat.replace(/_/g, ' ')}</span>
          ))}
        </div>
      )}

      {finding.findings && finding.findings.length > 0 && (
        <button
          onClick={() => setExpanded(!expanded)}
          style={{
            marginTop: 10, background: 'none', border: 'none', color: '#60a5fa',
            cursor: 'pointer', fontSize: 12, padding: 0, display: 'flex', alignItems: 'center', gap: 4,
          }}
        >
          {expanded ? '▲' : '▼'} {finding.findings.length} finding{finding.findings.length !== 1 ? 's' : ''}
        </button>
      )}

      {expanded && finding.findings && (
        <ul style={{ marginTop: 8, paddingLeft: 16, fontSize: 12, color: '#94a3b8', lineHeight: 1.6 }}>
          {finding.findings.map((f, i) => (
            <li key={i}>{f}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
