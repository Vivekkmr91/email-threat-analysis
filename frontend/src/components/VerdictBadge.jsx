import React from 'react';
import { verdictColors } from '../utils/helpers';

const icons = {
  malicious: '🔴',
  suspicious: '🟡',
  spam: '🔵',
  clean: '🟢',
  unknown: '⚪',
};

export default function VerdictBadge({ verdict, size = 'md' }) {
  const colors = verdictColors[verdict] || verdictColors.unknown;
  const sizeClasses = {
    sm: { fontSize: '11px', padding: '2px 8px' },
    md: { fontSize: '13px', padding: '4px 12px' },
    lg: { fontSize: '15px', padding: '6px 16px' },
  };

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      background: colors.bg,
      color: colors.text,
      border: `1px solid ${colors.border}`,
      borderRadius: '20px',
      fontWeight: 600,
      letterSpacing: '0.05em',
      textTransform: 'uppercase',
      whiteSpace: 'nowrap',
      ...sizeClasses[size],
    }}>
      <span>{icons[verdict] || '⚪'}</span>
      {verdict || 'unknown'}
    </span>
  );
}
