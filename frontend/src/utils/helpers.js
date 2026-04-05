export const verdictColors = {
  malicious: { bg: '#7f1d1d', text: '#fca5a5', border: '#ef4444', dot: '#ef4444' },
  suspicious: { bg: '#78350f', text: '#fde68a', border: '#f59e0b', dot: '#f59e0b' },
  spam: { bg: '#1e3a5f', text: '#93c5fd', border: '#3b82f6', dot: '#3b82f6' },
  clean: { bg: '#14532d', text: '#86efac', border: '#22c55e', dot: '#22c55e' },
  unknown: { bg: '#1e293b', text: '#94a3b8', border: '#475569', dot: '#475569' },
};

export const categoryLabels = {
  business_email_compromise: 'BEC',
  phishing: 'Phishing',
  malware: 'Malware',
  spam: 'Spam',
  quishing: 'QR Phishing',
  adversary_in_the_middle: 'AiTM',
  living_off_the_land: 'LotL',
  llm_generated_phishing: 'AI Phishing',
  deepfake_social_engineering: 'Deepfake',
  clean: 'Clean',
};

export const agentLabels = {
  text_analysis_agent: 'Text Analysis',
  metadata_agent: 'Metadata',
  enrichment_agent: 'Enrichment',
  graph_correlation_agent: 'Graph Correlation',
  decision_agent: 'Decision',
};

export const formatScore = (score) => `${(score * 100).toFixed(0)}%`;

export const formatDuration = (ms) => {
  if (!ms) return 'N/A';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
};

export const scoreToColor = (score) => {
  if (score >= 0.75) return '#ef4444';
  if (score >= 0.45) return '#f59e0b';
  if (score >= 0.25) return '#3b82f6';
  return '#22c55e';
};

export const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A';
  const d = new Date(dateStr);
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  });
};
