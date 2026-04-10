import React, { useEffect, useMemo, useState } from 'react';
import { emailAPI } from '../utils/api';

const GRAPH_REFRESH_MS = 30000;

const DEMO_NODES = [
  { id: '1', type: 'domain', label: 'paypa1.com', threat: 0.9 },
  { id: '2', type: 'domain', label: 'malicious-site.xyz', threat: 0.85 },
  { id: '3', type: 'email', label: 'attacker@evil.com', threat: 0.95 },
  { id: '4', type: 'email', label: 'ceo@fake-corp.net', threat: 0.8 },
  { id: '5', type: 'ip', label: '185.220.101.42', threat: 0.7 },
  { id: '6', type: 'campaign', label: 'Campaign: PayPal2024', threat: 0.9 },
  { id: '7', type: 'domain', label: 'micros0ft.com', threat: 0.88 },
  { id: '8', type: 'email', label: 'support@paypa1.com', threat: 0.92 },
  { id: '9', type: 'ip', label: '194.165.16.23', threat: 0.65 },
  { id: '10', type: 'domain', label: 'banc-of-america.xyz', threat: 0.75 },
];

const DEMO_EDGES = [
  { from: '3', to: '1', relationship: 'USES_DOMAIN' },
  { from: '3', to: '6', relationship: 'LINKED_TO' },
  { from: '1', to: '6', relationship: 'PART_OF' },
  { from: '5', to: '3', relationship: 'SOURCE_IP' },
  { from: '5', to: '4', relationship: 'SOURCE_IP' },
  { from: '4', to: '2', relationship: 'LINKS_TO' },
  { from: '8', to: '1', relationship: 'SPOOFED_DOMAIN' },
  { from: '8', to: '7', relationship: 'LOOKALIKE' },
  { from: '7', to: '6', relationship: 'PART_OF' },
  { from: '9', to: '8', relationship: 'SOURCE_IP' },
  { from: '9', to: '4', relationship: 'SOURCE_IP' },
  { from: '10', to: '2', relationship: 'LINKS_TO' },
];

const nodeColors = {
  domain: '#ef4444',
  email: '#f59e0b',
  ip: '#8b5cf6',
  campaign: '#3b82f6',
  entity: '#22c55e',
};

const nodeIcons = {
  domain: '🌐',
  email: '📧',
  ip: '🖥️',
  campaign: '⚡',
  entity: '🔎',
};

const layoutNodes = (nodes) => {
  if (!nodes.length) return [];
  const center = { x: 400, y: 250 };
  const baseRadius = 160;
  return nodes.map((node, index) => {
    const angle = (2 * Math.PI * index) / nodes.length;
    const radius = baseRadius + (index % 6) * 18;
    return {
      ...node,
      x: center.x + radius * Math.cos(angle),
      y: center.y + radius * Math.sin(angle),
    };
  });
};

export default function ThreatGraph() {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [useDemo, setUseDemo] = useState(false);

  useEffect(() => {
    if (useDemo) {
      return undefined;
    }
    let isMounted = true;

    const fetchSnapshot = async () => {
      try {
        const data = await emailAPI.getGraphSnapshot({ node_limit: 200, edge_limit: 400 });
        if (!isMounted) return;
        const nextNodes = (data.nodes || []).map((node) => ({
          id: node.node_id,
          type: node.node_type || 'entity',
          label: node.label || 'unknown',
          threat: node.threat_score || 0,
        }));
        const nextEdges = (data.edges || []).map((edge) => ({
          from: edge.source,
          to: edge.target,
          relationship: edge.relationship,
        }));
        setNodes(nextNodes);
        setEdges(nextEdges);
        setError(nextNodes.length ? null : 'No graph data yet. Run a few analyses to populate Neo4j.');
      } catch (err) {
        if (isMounted) {
          setError(err.message || 'Failed to load graph');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchSnapshot();
    const interval = setInterval(fetchSnapshot, GRAPH_REFRESH_MS);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [useDemo]);

  const positionedNodes = useMemo(() => layoutNodes(nodes), [nodes]);
  const filteredNodes = positionedNodes.filter((node) => filter === 'all' || node.type === filter);
  const nodeById = useMemo(
    () => Object.fromEntries(positionedNodes.map((node) => [node.id, node])),
    [positionedNodes]
  );

  const filteredEdges = edges.filter((edge) => {
    const from = nodeById[edge.from];
    const to = nodeById[edge.to];
    if (!from || !to) return false;
    if (filter === 'all') return true;
    return from.type === filter || to.type === filter;
  });

  const totalEntities = positionedNodes.length;
  const highRiskNodes = positionedNodes.filter((node) => node.threat > 0.75).length;
  const campaignCount = positionedNodes.filter((node) => node.type === 'campaign').length;

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9' }}>Threat Intelligence Graph</h1>
          <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
            Neo4j-powered relationship mapping between threat entities
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            type="button"
            onClick={() => {
              if (useDemo) {
                setUseDemo(false);
                setLoading(true);
                setNodes([]);
                setEdges([]);
                setSelected(null);
                setError(null);
                return;
              }
              setUseDemo(true);
              setNodes(DEMO_NODES);
              setEdges(DEMO_EDGES);
              setSelected(null);
              setError(null);
              setLoading(false);
            }}
            style={{
              background: '#1e293b',
              border: '1px solid #334155',
              color: '#94a3b8',
              padding: '6px 12px',
              borderRadius: 8,
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            {useDemo ? 'Use Live Data' : 'Show Demo Data'}
          </button>
          {['all', 'domain', 'email', 'ip', 'campaign'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '5px 12px',
                borderRadius: 6,
                border: '1px solid',
                borderColor: filter === f ? nodeColors[f] || '#3b82f6' : '#334155',
                background: filter === f ? (nodeColors[f] || '#3b82f6') + '20' : '#1e293b',
                color: filter === f ? nodeColors[f] || '#3b82f6' : '#94a3b8',
                cursor: 'pointer',
                fontSize: 12,
                fontWeight: filter === f ? 600 : 400,
                textTransform: 'capitalize',
              }}
            >
              {f === 'all' ? '⬤ All' : `${nodeIcons[f] || '🔎'} ${f}`}
            </button>
          ))}
        </div>
      </div>

      {(error || (!loading && nodes.length === 0 && !useDemo)) && (
        <div
          style={{
            marginBottom: 16,
            background: '#1e293b',
            border: '1px solid #334155',
            borderRadius: 12,
            padding: 16,
            color: '#94a3b8',
            fontSize: 13,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 16,
          }}
        >
          <div>
            <div style={{ fontWeight: 600, color: '#f1f5f9' }}>No graph data yet</div>
            <div style={{ marginTop: 4 }}>{error || 'Run analyses to populate Neo4j, or load demo data.'}</div>
          </div>
          {!useDemo && (
            <button
              type="button"
              onClick={() => {
                setUseDemo(true);
                setNodes(DEMO_NODES);
                setEdges(DEMO_EDGES);
                setSelected(null);
                setError(null);
                setLoading(false);
              }}
              style={{
                background: 'linear-gradient(135deg, #3b82f6, #2563eb)',
                border: 'none',
                color: '#fff',
                padding: '8px 14px',
                borderRadius: 8,
                fontSize: 12,
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              Load Demo Graph
            </button>
          )}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 16 }}>
        <div
          style={{
            background: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: 12,
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          <svg width="100%" height="500" viewBox="0 0 800 500" style={{ display: 'block' }}>
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />

            {filteredEdges.map((edge, i) => {
              const from = nodeById[edge.from];
              const to = nodeById[edge.to];
              if (!from || !to) return null;
              return (
                <line
                  key={`${edge.from}-${edge.to}-${i}`}
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke="#334155"
                  strokeWidth="1.5"
                  strokeDasharray="4 2"
                  opacity="0.6"
                />
              );
            })}

            {filteredNodes.map((node) => {
              const color = nodeColors[node.type] || '#94a3b8';
              const isSelected = selected?.id === node.id;
              const radius = 18 + node.threat * 14;
              return (
                <g key={node.id} onClick={() => setSelected(isSelected ? null : node)} style={{ cursor: 'pointer' }}>
                  <circle cx={node.x} cy={node.y} r={radius + 8} fill={color + '15'} stroke={color + '30'} strokeWidth="1" />
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={radius}
                    fill={color + (isSelected ? 'cc' : '40')}
                    stroke={color}
                    strokeWidth={isSelected ? 2.5 : 1.5}
                  />
                  <text x={node.x} y={node.y + 1} textAnchor="middle" dominantBaseline="middle" fontSize="14">
                    {nodeIcons[node.type] || '🔎'}
                  </text>
                  <text
                    x={node.x}
                    y={node.y + radius + 14}
                    textAnchor="middle"
                    fontSize="9"
                    fill="#94a3b8"
                    fontFamily="monospace"
                  >
                    {node.label.length > 18 ? node.label.substring(0, 18) + '…' : node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          <div
            style={{
              position: 'absolute',
              bottom: 12,
              left: 12,
              display: 'flex',
              gap: 12,
              background: '#0f172a90',
              backdropFilter: 'blur(8px)',
              padding: '6px 12px',
              borderRadius: 8,
            }}
          >
            {Object.entries(nodeIcons).map(([type, icon]) => (
              <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: '#94a3b8' }}>
                <span style={{ color: nodeColors[type] }}>●</span> {icon} {type}
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {loading && (
            <div
              style={{
                background: '#1e293b',
                border: '1px solid #334155',
                borderRadius: 12,
                padding: 20,
                textAlign: 'center',
                color: '#94a3b8',
                fontSize: 13,
              }}
            >
              Loading Neo4j graph snapshot…
            </div>
          )}
          {error && (
            <div
              style={{
                background: '#1e293b',
                border: '1px solid #ef4444',
                borderRadius: 12,
                padding: 16,
                color: '#fca5a5',
                fontSize: 13,
              }}
            >
              {error}
            </div>
          )}

          {selected ? (
            <div
              style={{
                background: '#1e293b',
                border: `1px solid ${nodeColors[selected.type] || '#64748b'}60`,
                borderRadius: 12,
                padding: 16,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                <span style={{ fontSize: 24 }}>{nodeIcons[selected.type] || '🔎'}</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 14, color: '#f1f5f9' }}>{selected.label}</div>
                  <div style={{ fontSize: 12, color: '#64748b', textTransform: 'capitalize' }}>{selected.type}</div>
                </div>
              </div>
              <div style={{ fontSize: 13 }}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    padding: '6px 0',
                    borderBottom: '1px solid #334155',
                  }}
                >
                  <span style={{ color: '#64748b' }}>Threat Score</span>
                  <span
                    style={{
                      color: selected.threat > 0.75 ? '#ef4444' : selected.threat > 0.4 ? '#f59e0b' : '#22c55e',
                      fontWeight: 700,
                    }}
                  >
                    {(selected.threat * 100).toFixed(0)}%
                  </span>
                </div>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    padding: '6px 0',
                    borderBottom: '1px solid #334155',
                  }}
                >
                  <span style={{ color: '#64748b' }}>Connections</span>
                  <span style={{ color: '#f1f5f9' }}>
                    {edges.filter((edge) => edge.from === selected.id || edge.to === selected.id).length}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                  <span style={{ color: '#64748b' }}>Status</span>
                  <span style={{ color: selected.threat > 0.75 ? '#ef4444' : '#f59e0b' }}>
                    {selected.threat > 0.75 ? 'Known Threat' : 'Under Review'}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div
              style={{
                background: '#1e293b',
                border: '1px solid #334155',
                borderRadius: 12,
                padding: 20,
                textAlign: 'center',
                color: '#475569',
                fontSize: 13,
              }}
            >
              Click a node to see details
            </div>
          )}

          <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 16 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: '#f1f5f9' }}>Graph Stats</div>
            {[
              { label: 'Total Entities', value: totalEntities },
              { label: 'Relationships', value: edges.length },
              { label: 'High-Risk Nodes', value: highRiskNodes },
              { label: 'Campaigns', value: campaignCount },
            ].map(({ label, value }) => (
              <div
                key={label}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  padding: '6px 0',
                  borderBottom: '1px solid #1e293b',
                  fontSize: 13,
                }}
              >
                <span style={{ color: '#64748b' }}>{label}</span>
                <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{value}</span>
              </div>
            ))}
          </div>

          <div
            style={{
              background: '#1e3a5f20',
              border: '1px solid #3b82f640',
              borderRadius: 8,
              padding: 12,
              fontSize: 12,
              color: '#93c5fd',
            }}
          >
            ℹ️ Graph snapshots refresh every 30 seconds. Ensure Neo4j is running for live data.
          </div>
        </div>
      </div>
    </div>
  );
}
