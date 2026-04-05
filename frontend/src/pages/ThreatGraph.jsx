import React, { useEffect, useRef, useState } from 'react';

// Simple SVG-based threat graph visualization
const MOCK_NODES = [
  { id: 1, type: 'domain', label: 'paypa1.com', threat: 0.9, x: 300, y: 150 },
  { id: 2, type: 'domain', label: 'malicious-site.xyz', threat: 0.85, x: 500, y: 200 },
  { id: 3, type: 'email', label: 'attacker@evil.com', threat: 0.95, x: 150, y: 300 },
  { id: 4, type: 'email', label: 'ceo@fake-corp.net', threat: 0.8, x: 450, y: 350 },
  { id: 5, type: 'ip', label: '185.220.101.42', threat: 0.7, x: 200, y: 450 },
  { id: 6, type: 'campaign', label: 'Campaign: PayPal2024', threat: 0.9, x: 380, y: 50 },
  { id: 7, type: 'domain', label: 'micros0ft.com', threat: 0.88, x: 600, y: 100 },
  { id: 8, type: 'email', label: 'support@paypa1.com', threat: 0.92, x: 550, y: 280 },
  { id: 9, type: 'ip', label: '194.165.16.23', threat: 0.65, x: 380, y: 450 },
  { id: 10, type: 'domain', label: 'banc-of-america.xyz', threat: 0.75, x: 680, y: 350 },
];

const MOCK_EDGES = [
  { from: 3, to: 1 }, { from: 3, to: 6 }, { from: 1, to: 6 },
  { from: 5, to: 3 }, { from: 5, to: 4 }, { from: 4, to: 2 },
  { from: 8, to: 1 }, { from: 8, to: 7 }, { from: 7, to: 6 },
  { from: 9, to: 8 }, { from: 9, to: 4 }, { from: 10, to: 2 },
];

const nodeColors = {
  domain: '#ef4444',
  email: '#f59e0b',
  ip: '#8b5cf6',
  campaign: '#3b82f6',
};

const nodeIcons = {
  domain: '🌐',
  email: '📧',
  ip: '🖥️',
  campaign: '⚡',
};

export default function ThreatGraph() {
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('all');

  const filteredNodes = MOCK_NODES.filter(n => filter === 'all' || n.type === filter);
  const filteredEdges = MOCK_EDGES.filter(e => {
    const from = filteredNodes.find(n => n.id === e.from);
    const to = filteredNodes.find(n => n.id === e.to);
    return from && to;
  });

  const nodeById = Object.fromEntries(MOCK_NODES.map(n => [n.id, n]));

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9' }}>Threat Intelligence Graph</h1>
          <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
            Neo4j-powered relationship mapping between threat entities
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {['all', 'domain', 'email', 'ip', 'campaign'].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              padding: '5px 12px', borderRadius: 6, border: '1px solid',
              borderColor: filter === f ? nodeColors[f] || '#3b82f6' : '#334155',
              background: filter === f ? (nodeColors[f] || '#3b82f6') + '20' : '#1e293b',
              color: filter === f ? nodeColors[f] || '#3b82f6' : '#94a3b8',
              cursor: 'pointer', fontSize: 12, fontWeight: filter === f ? 600 : 400,
              textTransform: 'capitalize',
            }}>{f === 'all' ? '⬤ All' : `${nodeIcons[f]} ${f}`}</button>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 16 }}>
        {/* Graph Canvas */}
        <div style={{
          background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12,
          position: 'relative', overflow: 'hidden',
        }}>
          <svg width="100%" height="500" viewBox="0 0 800 500" style={{ display: 'block' }}>
            {/* Background grid */}
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5"/>
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />

            {/* Edges */}
            {filteredEdges.map((e, i) => {
              const from = nodeById[e.from];
              const to = nodeById[e.to];
              if (!from || !to) return null;
              return (
                <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                  stroke="#334155" strokeWidth="1.5" strokeDasharray="4 2" opacity="0.6" />
              );
            })}

            {/* Nodes */}
            {filteredNodes.map(node => {
              const color = nodeColors[node.type] || '#94a3b8';
              const isSelected = selected?.id === node.id;
              const radius = 20 + (node.threat * 12);
              return (
                <g key={node.id} onClick={() => setSelected(isSelected ? null : node)} style={{ cursor: 'pointer' }}>
                  {/* Threat halo */}
                  <circle cx={node.x} cy={node.y} r={radius + 8}
                    fill={color + '15'} stroke={color + '30'} strokeWidth="1" />
                  {/* Main circle */}
                  <circle cx={node.x} cy={node.y} r={radius}
                    fill={color + (isSelected ? 'cc' : '40')}
                    stroke={color} strokeWidth={isSelected ? 2.5 : 1.5}
                  />
                  {/* Icon */}
                  <text x={node.x} y={node.y + 1} textAnchor="middle" dominantBaseline="middle" fontSize="14">
                    {nodeIcons[node.type]}
                  </text>
                  {/* Label */}
                  <text x={node.x} y={node.y + radius + 14} textAnchor="middle"
                    fontSize="9" fill="#94a3b8" fontFamily="monospace">
                    {node.label.length > 18 ? node.label.substring(0, 18) + '…' : node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Legend */}
          <div style={{
            position: 'absolute', bottom: 12, left: 12, display: 'flex', gap: 12,
            background: '#0f172a90', backdropFilter: 'blur(8px)', padding: '6px 12px', borderRadius: 8,
          }}>
            {Object.entries(nodeIcons).map(([type, icon]) => (
              <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#94a3b8' }}>
                <span style={{ color: nodeColors[type] }}>●</span> {icon} {type}
              </div>
            ))}
          </div>
        </div>

        {/* Node Details Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {selected ? (
            <div style={{ background: '#1e293b', border: `1px solid ${nodeColors[selected.type]}60`, borderRadius: 12, padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                <span style={{ fontSize: 24 }}>{nodeIcons[selected.type]}</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 14, color: '#f1f5f9' }}>
                    {selected.label}
                  </div>
                  <div style={{ fontSize: 12, color: '#64748b', textTransform: 'capitalize' }}>
                    {selected.type}
                  </div>
                </div>
              </div>
              <div style={{ fontSize: 13 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #334155' }}>
                  <span style={{ color: '#64748b' }}>Threat Score</span>
                  <span style={{
                    color: selected.threat > 0.75 ? '#ef4444' : selected.threat > 0.4 ? '#f59e0b' : '#22c55e',
                    fontWeight: 700,
                  }}>{(selected.threat * 100).toFixed(0)}%</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #334155' }}>
                  <span style={{ color: '#64748b' }}>Connections</span>
                  <span style={{ color: '#f1f5f9' }}>
                    {MOCK_EDGES.filter(e => e.from === selected.id || e.to === selected.id).length}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                  <span style={{ color: '#64748b' }}>Status</span>
                  <span style={{ color: '#ef4444' }}>Known Threat</span>
                </div>
              </div>
            </div>
          ) : (
            <div style={{
              background: '#1e293b', border: '1px solid #334155', borderRadius: 12,
              padding: 20, textAlign: 'center', color: '#475569', fontSize: 13,
            }}>
              Click a node to see details
            </div>
          )}

          {/* Stats */}
          <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 16 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: '#f1f5f9' }}>Graph Stats</div>
            {[
              { label: 'Total Entities', value: MOCK_NODES.length },
              { label: 'Relationships', value: MOCK_EDGES.length },
              { label: 'High-Risk Nodes', value: MOCK_NODES.filter(n => n.threat > 0.75).length },
              { label: 'Campaigns', value: MOCK_NODES.filter(n => n.type === 'campaign').length },
            ].map(({ label, value }) => (
              <div key={label} style={{
                display: 'flex', justifyContent: 'space-between', padding: '6px 0',
                borderBottom: '1px solid #1e293b', fontSize: 13,
              }}>
                <span style={{ color: '#64748b' }}>{label}</span>
                <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{value}</span>
              </div>
            ))}
          </div>

          {/* Note */}
          <div style={{
            background: '#1e3a5f20', border: '1px solid #3b82f640', borderRadius: 8,
            padding: 12, fontSize: 12, color: '#93c5fd',
          }}>
            ℹ️ This graph represents Neo4j-stored threat intelligence. In production, nodes are populated from real email analysis data.
          </div>
        </div>
      </div>
    </div>
  );
}
