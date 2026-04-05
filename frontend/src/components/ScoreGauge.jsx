import React from 'react';
import { scoreToColor } from '../utils/helpers';

export default function ScoreGauge({ score = 0, size = 120 }) {
  const radius = (size / 2) - 12;
  const circumference = 2 * Math.PI * radius;
  const progress = score * circumference;
  const color = scoreToColor(score);

  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#1e293b"
          strokeWidth="10"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${progress} ${circumference}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1s ease' }}
        />
      </svg>
      <div style={{
        position: 'absolute',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        textAlign: 'center',
      }}>
        <div style={{ fontSize: size * 0.22, fontWeight: 700, color }}>
          {(score * 100).toFixed(0)}
        </div>
        <div style={{ fontSize: size * 0.11, color: '#64748b', marginTop: -2 }}>%</div>
      </div>
    </div>
  );
}
