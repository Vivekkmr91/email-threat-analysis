import React, { useState } from 'react';
import { emailAPI } from '../utils/api';
import VerdictBadge from '../components/VerdictBadge';
import ScoreGauge from '../components/ScoreGauge';
import AgentCard from '../components/AgentCard';
import { formatDuration, categoryLabels, formatDate } from '../utils/helpers';
import ReactMarkdown from 'react-markdown';

const SAMPLE_PHISHING = {
  subject: "URGENT: Verify Your Account - Unusual Activity Detected",
  sender: "security-alerts@paypa1-secure.com",
  recipients: ["user@company.com"],
  body_text: `Dear Valued Customer,

We have detected unusual activity on your PayPal account. To protect your account, we have temporarily limited access.

Please click the link below to verify your identity and restore your account access immediately:

https://secure.paypa1-verify.xyz/login?returnurl=https://paypal.com

This link expires in 24 hours. Failure to verify will result in permanent account suspension.

PayPal Security Team`,
  headers: {
    "Reply-To": "attacker@evil-domain.tk",
    "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
    "X-Originating-IP": "185.220.101.42"
  }
};

const SAMPLE_BEC = {
  subject: "Payment Request - Invoice #8734",
  sender: "ceo@company-corp.net",
  recipients: ["finance@mycompany.com"],
  body_text: `Hi,

I need you to process an urgent wire transfer of $85,000 to our new vendor. 
Please update the banking details and transfer immediately. This is time-sensitive.

New bank account:
Account Name: Vendor Inc
Routing: 021000089
Account: 4839201847

Please confirm once done. Keep this confidential until the deal is finalized.

Best,
Robert Johnson
CEO`,
  headers: {}
};

export default function AnalyzeEmail() {
  const [mode, setMode] = useState('form'); // 'form' or 'raw'
  const [form, setForm] = useState({
    subject: '', sender: '', recipients: '', body_text: '', body_html: '',
    headers_raw: '', source: 'api',
  });
  const [rawEmail, setRawEmail] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [feedback, setFeedback] = useState(null);

  const loadSample = (sample) => {
    setForm({
      subject: sample.subject,
      sender: sample.sender,
      recipients: sample.recipients.join(', '),
      body_text: sample.body_text,
      body_html: '',
      headers_raw: JSON.stringify(sample.headers, null, 2),
      source: 'api',
    });
    setMode('form');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let payload;
      if (mode === 'raw') {
        payload = { raw_email: rawEmail, source: 'api' };
      } else {
        let headers = {};
        try { headers = JSON.parse(form.headers_raw || '{}'); } catch {}
        payload = {
          subject: form.subject,
          sender: form.sender,
          recipients: form.recipients.split(',').map(r => r.trim()).filter(Boolean),
          body_text: form.body_text,
          body_html: form.body_html,
          headers,
          source: form.source,
        };
      }
      const data = await emailAPI.analyzeEmail(payload);
      setResult(data);
      setActiveTab('overview');
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const submitFeedback = async (type) => {
    if (!result) return;
    try {
      await emailAPI.submitFeedback(result.analysis_id, { feedback_type: type });
      setFeedback(type);
    } catch (e) {
      console.error('Feedback failed', e);
    }
  };

  return (
    <div style={{ padding: 24, display: 'grid', gridTemplateColumns: result ? '1fr 1fr' : '1fr', gap: 24 }}>
      {/* Left: Input Form */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9' }}>Analyze Email</h1>
            <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>Submit an email for multi-agent threat analysis</p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => loadSample(SAMPLE_PHISHING)} style={btnStyle('#1e293b')}>
              📧 Phishing Sample
            </button>
            <button onClick={() => loadSample(SAMPLE_BEC)} style={btnStyle('#1e293b')}>
              💼 BEC Sample
            </button>
          </div>
        </div>

        {/* Mode Toggle */}
        <div style={{ display: 'flex', gap: 0, marginBottom: 16, background: '#1e293b', borderRadius: 8, padding: 4, width: 'fit-content' }}>
          {['form', 'raw'].map(m => (
            <button key={m} onClick={() => setMode(m)} style={{
              padding: '6px 16px', borderRadius: 6, border: 'none', cursor: 'pointer',
              background: mode === m ? '#3b82f6' : 'transparent',
              color: mode === m ? '#fff' : '#64748b', fontSize: 13, fontWeight: mode === m ? 600 : 400,
            }}>
              {m === 'form' ? 'Form Input' : 'Raw EML'}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit}>
          {mode === 'form' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <Field label="Subject" value={form.subject} onChange={v => setForm({...form, subject: v})} placeholder="Email subject line" />
              <Field label="Sender" value={form.sender} onChange={v => setForm({...form, sender: v})} placeholder="sender@domain.com" />
              <Field label="Recipients" value={form.recipients} onChange={v => setForm({...form, recipients: v})} placeholder="recipient@domain.com (comma-separated)" />
              <TextArea label="Body (Plain Text)" value={form.body_text} onChange={v => setForm({...form, body_text: v})} rows={8} placeholder="Email body text..." />
              <TextArea label="Headers (JSON)" value={form.headers_raw} onChange={v => setForm({...form, headers_raw: v})} rows={4} placeholder='{"Reply-To": "...", "Authentication-Results": "spf=fail"}' mono />
            </div>
          ) : (
            <TextArea label="Raw Email (RFC 2822 / EML format)" value={rawEmail} onChange={setRawEmail} rows={16} placeholder="Paste raw email here..." mono />
          )}

          {error && (
            <div style={{ marginTop: 12, padding: 12, background: '#7f1d1d20', border: '1px solid #ef444440', borderRadius: 8, fontSize: 13, color: '#fca5a5' }}>
              ⚠️ {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              marginTop: 16, width: '100%', padding: '12px', borderRadius: 8, border: 'none',
              background: loading ? '#1e293b' : 'linear-gradient(135deg, #3b82f6, #2563eb)',
              color: loading ? '#64748b' : '#fff', fontSize: 15, fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            }}
          >
            {loading ? (
              <>
                <span className="spinner" style={{ display: 'inline-block', width: 16, height: 16, border: '2px solid #475569', borderTop: '2px solid #3b82f6', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
                Analyzing with {loading ? '5' : ''} AI Agents...
              </>
            ) : '🔍 Analyze Email'}
          </button>
        </form>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>

      {/* Right: Results */}
      {result && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: '#f1f5f9' }}>Analysis Result</h2>
            <div style={{ fontSize: 12, color: '#64748b' }}>
              {formatDuration(result.analysis_duration_ms)} • {result.agents_triggered?.length || 0} agents
            </div>
          </div>

          {/* Verdict Banner */}
          <div style={{
            background: result.verdict === 'malicious' ? '#7f1d1d20' :
              result.verdict === 'suspicious' ? '#78350f20' :
              result.verdict === 'spam' ? '#1e3a5f20' : '#14532d20',
            border: `1px solid ${result.verdict === 'malicious' ? '#ef4444' : result.verdict === 'suspicious' ? '#f59e0b' : result.verdict === 'spam' ? '#3b82f6' : '#22c55e'}40`,
            borderRadius: 12, padding: 20, marginBottom: 16,
            display: 'flex', alignItems: 'center', gap: 20,
          }}>
            <ScoreGauge score={result.threat_score} size={80} />
            <div>
              <VerdictBadge verdict={result.verdict} size="lg" />
              <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {result.threat_categories?.map((cat, i) => (
                  <span key={i} style={{
                    fontSize: 11, padding: '2px 8px', borderRadius: 10,
                    background: '#0f172a', color: '#94a3b8', border: '1px solid #334155',
                  }}>
                    {categoryLabels[cat] || cat}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 0, marginBottom: 16, borderBottom: '1px solid #1e293b' }}>
            {['overview', 'agents', 'urls', 'reasoning', 'actions'].map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} style={{
                padding: '8px 14px', border: 'none', cursor: 'pointer', background: 'transparent',
                color: activeTab === tab ? '#3b82f6' : '#64748b', fontSize: 13, fontWeight: activeTab === tab ? 600 : 400,
                borderBottom: activeTab === tab ? '2px solid #3b82f6' : '2px solid transparent',
                textTransform: 'capitalize',
              }}>{tab}</button>
            ))}
          </div>

          {/* Tab Content */}
          {activeTab === 'overview' && (
            <div style={{ fontSize: 13 }}>
              <InfoRow label="Analysis ID" value={<code style={{ fontSize: 11, color: '#94a3b8' }}>{result.analysis_id}</code>} />
              <InfoRow label="Analyzed at" value={formatDate(result.created_at)} />
              <InfoRow label="URLs found" value={result.url_results?.length || 0} />
              <InfoRow label="Attachments" value={result.attachment_results?.length || 0} />
              <InfoRow label="Malicious URLs" value={result.url_results?.filter(u => u.is_malicious).length || 0} />
              <InfoRow label="Analysis time" value={formatDuration(result.analysis_duration_ms)} />
            </div>
          )}

          {activeTab === 'agents' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {result.agent_findings?.map((finding, i) => (
                <AgentCard key={i} finding={finding} />
              ))}
            </div>
          )}

          {activeTab === 'urls' && (
            <div>
              {result.url_results?.length === 0 ? (
                <div style={{ color: '#64748b', textAlign: 'center', padding: 20 }}>No URLs found</div>
              ) : result.url_results?.map((url, i) => (
                <div key={i} style={{
                  background: '#1e293b', border: `1px solid ${url.is_malicious ? '#ef444440' : '#334155'}`,
                  borderRadius: 8, padding: 12, marginBottom: 8, fontSize: 12,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                    <div style={{ color: url.is_malicious ? '#fca5a5' : '#94a3b8', wordBreak: 'break-all', flex: 1 }}>
                      {url.url.length > 80 ? url.url.substring(0, 80) + '...' : url.url}
                    </div>
                    {url.is_malicious && <span style={{ background: '#7f1d1d', color: '#fca5a5', padding: '2px 8px', borderRadius: 6, whiteSpace: 'nowrap', fontSize: 11 }}>MALICIOUS</span>}
                    {url.is_look_alike && <span style={{ background: '#78350f', color: '#fde68a', padding: '2px 8px', borderRadius: 6, whiteSpace: 'nowrap', fontSize: 11 }}>LOOK-ALIKE</span>}
                  </div>
                  {url.look_alike_target && <div style={{ color: '#64748b', marginTop: 4 }}>Mimics: {url.look_alike_target}</div>}
                  {url.is_qr_code_url && <div style={{ color: '#a78bfa', marginTop: 4 }}>📱 Extracted from QR code</div>}
                </div>
              ))}
            </div>
          )}

          {activeTab === 'reasoning' && (
            <div style={{
              background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8,
              padding: 16, fontSize: 12, lineHeight: 1.7, color: '#94a3b8', maxHeight: 400, overflowY: 'auto',
            }}>
              <ReactMarkdown>{result.reasoning_trace || 'No reasoning trace available'}</ReactMarkdown>
            </div>
          )}

          {activeTab === 'actions' && (
            <div>
              {result.recommended_actions?.map((action, i) => (
                <div key={i} style={{
                  background: '#1e293b', border: '1px solid #334155', borderRadius: 8,
                  padding: '10px 14px', marginBottom: 8, fontSize: 13, color: '#e2e8f0',
                  display: 'flex', alignItems: 'center', gap: 10,
                }}>
                  <span style={{ fontSize: 16 }}>
                    {action.startsWith('QUARANTINE') ? '🔒' :
                     action.startsWith('BLOCK') ? '🚫' :
                     action.startsWith('ALERT') ? '🚨' :
                     action.startsWith('CLEAN') ? '✅' : '📋'}
                  </span>
                  {action}
                </div>
              ))}
            </div>
          )}

          {/* Feedback Section */}
          <div style={{ marginTop: 20, padding: 16, background: '#1e293b', borderRadius: 8 }}>
            <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 10 }}>
              🧑‍💻 Analyst Feedback (Human-in-the-Loop)
            </div>
            {feedback ? (
              <div style={{ color: '#22c55e', fontSize: 13 }}>✓ Feedback submitted: {feedback}</div>
            ) : (
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => submitFeedback('correct')} style={btnStyle('#14532d', '#22c55e')}>✓ Correct</button>
                <button onClick={() => submitFeedback('false_positive')} style={btnStyle('#1e3a5f', '#3b82f6')}>⚠ False Positive</button>
                <button onClick={() => submitFeedback('false_negative')} style={btnStyle('#7f1d1d', '#ef4444')}>⚠ Missed Threat</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const Field = ({ label, value, onChange, placeholder }) => (
  <div>
    <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>{label}</label>
    <input
      value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      style={{
        width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#f1f5f9',
        padding: '8px 12px', borderRadius: 6, fontSize: 13, outline: 'none',
      }}
    />
  </div>
);

const TextArea = ({ label, value, onChange, rows = 4, placeholder, mono }) => (
  <div>
    <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>{label}</label>
    <textarea
      value={value} onChange={e => onChange(e.target.value)} rows={rows} placeholder={placeholder}
      style={{
        width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#f1f5f9',
        padding: '8px 12px', borderRadius: 6, fontSize: mono ? 12 : 13,
        fontFamily: mono ? "'JetBrains Mono', monospace" : 'inherit',
        outline: 'none', resize: 'vertical',
      }}
    />
  </div>
);

const InfoRow = ({ label, value }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #1e293b' }}>
    <span style={{ color: '#64748b' }}>{label}</span>
    <span style={{ color: '#f1f5f9', fontWeight: 500 }}>{value}</span>
  </div>
);

const btnStyle = (bg, border) => ({
  padding: '6px 14px', borderRadius: 6, border: `1px solid ${border || '#334155'}`,
  background: bg, color: '#f1f5f9', cursor: 'pointer', fontSize: 12, fontWeight: 500,
});
