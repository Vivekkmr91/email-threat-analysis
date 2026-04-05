import React, { useState, useEffect } from 'react';
import {
  Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement,
  PointElement, ArcElement, Title, Tooltip, Legend, Filler,
} from 'chart.js';
import { Bar, Line, Doughnut } from 'react-chartjs-2';
import { emailAPI } from '../utils/api';
import { formatDuration } from '../utils/helpers';

ChartJS.register(
  CategoryScale, LinearScale, BarElement, LineElement, PointElement,
  ArcElement, Title, Tooltip, Legend, Filler
);

const StatCard = ({ label, value, color = '#3b82f6', icon }) => (
  <div style={{
    background: '#1e293b', border: `1px solid ${color}30`, borderRadius: 12,
    padding: '20px', flex: 1, minWidth: 140,
  }}>
    <div style={{ fontSize: 28, marginBottom: 4 }}>{icon}</div>
    <div style={{ fontSize: 28, fontWeight: 700, color }}>{value?.toLocaleString() ?? '—'}</div>
    <div style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>{label}</div>
  </div>
);

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(30);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const data = await emailAPI.getDashboardStats(days);
        setStats(data);
      } catch (e) {
        console.error('Failed to load stats', e);
      } finally {
        setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [days]);

  if (loading && !stats) {
    return <div style={{ padding: 32, color: '#64748b', textAlign: 'center' }}>Loading dashboard...</div>;
  }

  const verdictData = {
    labels: ['Malicious', 'Suspicious', 'Spam', 'Clean'],
    datasets: [{
      data: [stats?.malicious_count, stats?.suspicious_count, stats?.spam_count, stats?.clean_count],
      backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#22c55e'],
      borderWidth: 0,
      hoverOffset: 6,
    }],
  };

  const timelineData = {
    labels: (stats?.threats_over_time || []).map(d => d.date),
    datasets: [
      {
        label: 'Malicious',
        data: (stats?.threats_over_time || []).map(d => d.malicious || 0),
        borderColor: '#ef4444', backgroundColor: '#ef444420', fill: true, tension: 0.4,
      },
      {
        label: 'Suspicious',
        data: (stats?.threats_over_time || []).map(d => d.suspicious || 0),
        borderColor: '#f59e0b', backgroundColor: '#f59e0b20', fill: true, tension: 0.4,
      },
      {
        label: 'Clean',
        data: (stats?.threats_over_time || []).map(d => d.clean || 0),
        borderColor: '#22c55e', backgroundColor: '#22c55e15', fill: true, tension: 0.4,
      },
    ],
  };

  const domainData = {
    labels: (stats?.top_sender_domains || []).map(d => d.domain),
    datasets: [{
      label: 'Threat Emails',
      data: (stats?.top_sender_domains || []).map(d => d.count),
      backgroundColor: '#ef444480',
      borderColor: '#ef4444',
      borderWidth: 1,
      borderRadius: 4,
    }],
  };

  const chartOptions = {
    responsive: true,
    plugins: {
      legend: { labels: { color: '#94a3b8', font: { size: 12 } } },
    },
    scales: {
      x: { ticks: { color: '#64748b', font: { size: 11 } }, grid: { color: '#1e293b' } },
      y: { ticks: { color: '#64748b', font: { size: 11 } }, grid: { color: '#1e293b' } },
    },
  };

  return (
    <div style={{ padding: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9' }}>SOC Dashboard</h1>
          <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
            Real-time email threat intelligence overview
          </p>
        </div>
        <select
          value={days}
          onChange={e => setDays(Number(e.target.value))}
          style={{
            background: '#1e293b', border: '1px solid #334155', color: '#94a3b8',
            padding: '6px 12px', borderRadius: 8, fontSize: 13, cursor: 'pointer',
          }}
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
      </div>

      {/* Stat Cards */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 24, flexWrap: 'wrap' }}>
        <StatCard icon="📧" label="Total Analyzed" value={stats?.total_analyzed} color="#3b82f6" />
        <StatCard icon="🔴" label="Malicious" value={stats?.malicious_count} color="#ef4444" />
        <StatCard icon="🟡" label="Suspicious" value={stats?.suspicious_count} color="#f59e0b" />
        <StatCard icon="🟢" label="Clean" value={stats?.clean_count} color="#22c55e" />
        <StatCard icon="⏱️" label="Avg Analysis Time" value={formatDuration(stats?.avg_analysis_time_ms)} color="#8b5cf6" />
        <StatCard icon="🎯" label="Detection Rate" value={stats ? `${(stats.detection_rate * 100).toFixed(1)}%` : null} color="#06b6d4" />
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 16, marginBottom: 16 }}>
        {/* Timeline */}
        <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 20 }}>
          <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 16, color: '#f1f5f9' }}>
            Threat Timeline
          </h2>
          {(stats?.threats_over_time || []).length > 0 ? (
            <Line data={timelineData} options={{ ...chartOptions, maintainAspectRatio: false }} height={200} />
          ) : (
            <div style={{ textAlign: 'center', color: '#475569', padding: 40 }}>
              No threat data for selected period
            </div>
          )}
        </div>

        {/* Verdict Distribution */}
        <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 20 }}>
          <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 16, color: '#f1f5f9' }}>
            Verdict Distribution
          </h2>
          <Doughnut
            data={verdictData}
            options={{
              responsive: true,
              cutout: '65%',
              plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } } },
            }}
          />
        </div>
      </div>

      {/* Top Threat Domains */}
      {(stats?.top_sender_domains || []).length > 0 && (
        <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 12, padding: 20 }}>
          <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 16, color: '#f1f5f9' }}>
            Top Threat Sender Domains
          </h2>
          <Bar data={domainData} options={{ ...chartOptions, maintainAspectRatio: false }} height={160} />
        </div>
      )}

      {/* False Positive Rate Alert */}
      {stats && stats.false_positive_rate > 0.01 && (
        <div style={{
          marginTop: 16, background: '#78350f20', border: '1px solid #f59e0b40',
          borderRadius: 12, padding: 16, display: 'flex', alignItems: 'center', gap: 12,
        }}>
          <span style={{ fontSize: 20 }}>⚠️</span>
          <div>
            <div style={{ fontWeight: 600, color: '#fde68a', fontSize: 14 }}>
              High False Positive Rate: {(stats.false_positive_rate * 100).toFixed(2)}%
            </div>
            <div style={{ color: '#92400e', fontSize: 12, marginTop: 2 }}>
              Consider reviewing detection thresholds or providing more analyst feedback
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
