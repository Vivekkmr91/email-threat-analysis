"""
Feature Engineering for Phishing / LLM-Generated Email Detection.

Extracts a fixed-length numerical feature vector from an email that can
be consumed by any scikit-learn compatible classifier or a neural network.

Feature Groups
--------------
1.  Linguistic / readability  (15 features)
2.  Structural / formatting   (10 features)
3.  Urgency / social-eng.     (10 features)
4.  Lexical LLM fingerprints  (12 features)
5.  URL / domain signals      (8  features)
6.  Header / auth signals     (5  features)
                               ─────────────
                               60 total features
"""
from __future__ import annotations

import math
import re
import unicodedata
from typing import Dict, Any, List, Optional
import numpy as np


# ──────────────────────────────────────────────────────────────────────────────
# Compiled regex patterns (module-level for speed)
# ──────────────────────────────────────────────────────────────────────────────

_RE_URL         = re.compile(r'https?://\S+', re.IGNORECASE)
_RE_WORD        = re.compile(r'\b[a-zA-Z]+\b')
_RE_SENTENCE    = re.compile(r'[.!?]+')
_RE_WHITESPACE  = re.compile(r'\s+')
_RE_PUNCT       = re.compile(r'[^\w\s]')
_RE_DIGITS      = re.compile(r'\d')
_RE_ALLCAPS     = re.compile(r'\b[A-Z]{3,}\b')
_RE_MONEY       = re.compile(r'\$[\d,]+|\b\d+\s*(dollars?|USD|EUR|GBP)\b', re.I)

# Social engineering keyword groups
_URGENCY_WORDS = frozenset([
    'urgent', 'immediately', 'asap', 'deadline', 'expire', 'suspended',
    'limited', 'act now', 'final notice', 'last chance', 'critical',
    'alert', 'warning', 'attention required', 'time-sensitive', 'hurry',
])
_AUTH_WORDS = frozenset([
    'ceo', 'cfo', 'president', 'director', 'executive', 'management',
    'official', 'authorized', 'mandatory', 'required', 'compliance',
])
_CREDENTIAL_WORDS = frozenset([
    'password', 'username', 'login', 'verify', 'credential', 'account',
    'sign in', 'secure', 'reset', 'confirm', 'update your', 'click here',
])
_FINANCIAL_WORDS = frozenset([
    'wire transfer', 'bank account', 'routing number', 'swift', 'iban',
    'invoice', 'payment', 'transfer', 'funds', 'deposit', 'refund',
])

# LLM "tell" phrase patterns (overly formal / AI-sounding constructions)
_LLM_PHRASES = [
    r'\bI hope (this email finds you|this message finds you)\b',
    r'\bplease (be advised|note that|be informed)\b',
    r'\bkindly (be advised|note|ensure|confirm)\b',
    r'\bshould you (have any questions|require any assistance|need any)\b',
    r'\bdo not hesitate to (contact|reach out|ask)\b',
    r'\b(rest assured|rest easy) that\b',
    r'\bwe (sincerely|greatly|deeply) (apologize|regret|thank)\b',
    r'\bthank you for your (prompt|continued|valued|kind) (attention|cooperation|support)\b',
    r'\byour (immediate|prompt|urgent) attention\b',
    r'\bplease find (attached|below|enclosed)\b',
]
_RE_LLM_PHRASES = [re.compile(p, re.IGNORECASE) for p in _LLM_PHRASES]

# Legitimate/personal language markers (low in LLM-generated phishing)
_PERSONAL_MARKERS = [
    r'\b(hey|hi|hello) \w+\b',       # informal greeting with name
    r"\bi('m| am) \w+\b",            # personal intro
    r'\bremember when\b',
    r'\byesterday\b|\blast (week|month)\b',
    r'\bour (meeting|call|conversation|discussion)\b',
    r'\bby the way\b|\bbtw\b',
    r'\bcatch up\b|\bcheck in\b',
]
_RE_PERSONAL = [re.compile(p, re.IGNORECASE) for p in _PERSONAL_MARKERS]

FEATURE_NAMES: List[str] = []  # populated at bottom of file


# ──────────────────────────────────────────────────────────────────────────────
# Main extraction entry point
# ──────────────────────────────────────────────────────────────────────────────

def extract_features(
    subject: str,
    body: str,
    sender: str = "",
    headers: Optional[Dict[str, str]] = None,
    urls: Optional[List[str]] = None,
) -> np.ndarray:
    """
    Extract a 60-element float32 feature vector from an email.

    Parameters
    ----------
    subject : str   Email subject line
    body    : str   Plain-text body (HTML stripped externally)
    sender  : str   Sender address / display name
    headers : dict  Raw email headers {name: value}
    urls    : list  List of URLs found in the email

    Returns
    -------
    np.ndarray  shape (60,) dtype float32
    """
    headers = headers or {}
    urls = urls or []
    full_text = f"{subject}\n{body}"

    feats: List[float] = []

    # ── Group 1: Linguistic / readability (15) ──────────────────────────────
    feats.extend(_linguistic_features(body, subject))

    # ── Group 2: Structural / formatting (10) ───────────────────────────────
    feats.extend(_structural_features(body))

    # ── Group 3: Urgency / social engineering (10) ──────────────────────────
    feats.extend(_social_engineering_features(full_text))

    # ── Group 4: LLM fingerprint (12) ───────────────────────────────────────
    feats.extend(_llm_fingerprint_features(body, subject))

    # ── Group 5: URL / domain signals (8) ───────────────────────────────────
    feats.extend(_url_features(urls, body))

    # ── Group 6: Header / auth signals (5) ──────────────────────────────────
    feats.extend(_header_features(headers, sender))

    vec = np.array(feats, dtype=np.float32)
    assert vec.shape == (60,), f"Feature vector length mismatch: {vec.shape}"
    return vec


# ──────────────────────────────────────────────────────────────────────────────
# Group implementations
# ──────────────────────────────────────────────────────────────────────────────

def _linguistic_features(body: str, subject: str) -> List[float]:
    """15 linguistic / readability features."""
    text = body.strip()
    words = _RE_WORD.findall(text)
    sentences = [s for s in _RE_SENTENCE.split(text) if s.strip()]
    n_words = max(len(words), 1)
    n_sent  = max(len(sentences), 1)

    # 1. Word count (log-normalised, cap at log(3000))
    word_count_norm = min(math.log1p(len(words)) / math.log(3001), 1.0)

    # 2. Avg sentence length (words / sentence), cap at 40
    avg_sent_len = min(n_words / n_sent / 40.0, 1.0)

    # 3. Sentence length variance (proxy for style uniformity)
    sent_lengths = [len(_RE_WORD.findall(s)) for s in sentences]
    variance = (sum((l - (sum(sent_lengths)/n_sent))**2 for l in sent_lengths)
                / n_sent) if n_sent > 1 else 0.0
    variance_norm = min(variance / 200.0, 1.0)   # high = diverse = less LLM-like

    # 4. Type-token ratio (unique words / total words) – low = repetitive
    ttr = len(set(w.lower() for w in words)) / n_words

    # 5. Punctuation ratio
    n_punct = len(_RE_PUNCT.findall(text))
    punct_ratio = min(n_punct / max(len(text), 1), 0.3) / 0.3

    # 6. Digit ratio
    n_digits = len(_RE_DIGITS.findall(text))
    digit_ratio = min(n_digits / max(len(text), 1), 0.2) / 0.2

    # 7. ALL-CAPS word ratio
    allcaps = _RE_ALLCAPS.findall(text)
    allcaps_ratio = min(len(allcaps) / n_words, 0.5) / 0.5

    # 8. Money amounts mentioned
    money_count = len(_RE_MONEY.findall(text))
    money_norm  = min(money_count / 5.0, 1.0)

    # 9. Avg word length
    avg_word_len = min(sum(len(w) for w in words) / n_words / 12.0, 1.0)

    # 10. Gunning Fog index approximation (normalised)
    hard_words = [w for w in words if len(w) > 2 and
                  sum(1 for c in 'aeiou' if c in w.lower()) >= 3]
    fog_raw    = 0.4 * (n_words / n_sent + 100 * len(hard_words) / n_words)
    fog_norm   = min(fog_raw / 30.0, 1.0)

    # 11. Has HTML markup indicators (leaked into text)
    has_html = 1.0 if re.search(r'<[a-z]+[\s>]', body, re.I) else 0.0

    # 12. Emoji presence
    has_emoji = 1.0 if any(
        unicodedata.category(c) in ('So', 'Sm') for c in body
    ) else 0.0

    # 13. Exclamation density
    excl = body.count('!')
    excl_norm = min(excl / 10.0, 1.0)

    # 14. Question density
    quest = body.count('?')
    quest_norm = min(quest / 5.0, 1.0)

    # 15. Subject length (normalised)
    subj_len_norm = min(len(subject) / 200.0, 1.0)

    return [
        word_count_norm, avg_sent_len, variance_norm, ttr, punct_ratio,
        digit_ratio, allcaps_ratio, money_norm, avg_word_len, fog_norm,
        has_html, has_emoji, excl_norm, quest_norm, subj_len_norm,
    ]


def _structural_features(body: str) -> List[float]:
    """10 structural / formatting features."""
    lines = body.split('\n')
    n_lines = max(len(lines), 1)

    # 1. Total character count (log-norm)
    char_count_norm = min(math.log1p(len(body)) / math.log(10001), 1.0)

    # 2. Blank line ratio
    blank_lines = sum(1 for l in lines if not l.strip())
    blank_ratio = blank_lines / n_lines

    # 3. Line count (log-norm)
    line_count_norm = min(math.log1p(n_lines) / math.log(201), 1.0)

    # 4. Has salutation (Dear / Hello / Hi)
    has_salutation = 1.0 if re.search(
        r'\b(dear|hello|hi|greetings|good (morning|afternoon|evening))\b',
        body[:200], re.I
    ) else 0.0

    # 5. Has professional closing
    has_closing = 1.0 if re.search(
        r'\b(sincerely|regards|best regards|yours (truly|faithfully)|thank you)\b',
        body[-300:], re.I
    ) else 0.0

    # 6. Has unsubscribe text
    has_unsub = 1.0 if re.search(
        r'\b(unsubscribe|opt.out|remove me)\b', body, re.I
    ) else 0.0

    # 7. Has disclaimer
    has_disclaimer = 1.0 if re.search(
        r'\b(confidential|privileged|intended recipient|legal notice)\b', body, re.I
    ) else 0.0

    # 8. Paragraph count (heuristic: blank-line separated blocks)
    paragraphs = [p for p in re.split(r'\n\s*\n', body) if p.strip()]
    para_norm = min(len(paragraphs) / 10.0, 1.0)

    # 9. Short paragraph ratio (< 5 words) — common in phishing
    short_para = sum(1 for p in paragraphs if len(p.split()) < 5)
    short_para_ratio = short_para / max(len(paragraphs), 1)

    # 10. Has bullet points / numbered list
    has_list = 1.0 if re.search(
        r'(^\s*[-•*]\s|\d+\.\s)', body, re.MULTILINE
    ) else 0.0

    return [
        char_count_norm, blank_ratio, line_count_norm, has_salutation,
        has_closing, has_unsub, has_disclaimer, para_norm,
        short_para_ratio, has_list,
    ]


def _social_engineering_features(text: str) -> List[float]:
    """10 social-engineering / urgency features."""
    text_lower = text.lower()
    words_set  = set(text_lower.split())

    # 1. Urgency word density
    urgency_hits = sum(1 for w in _URGENCY_WORDS if w in text_lower)
    urgency_norm = min(urgency_hits / 5.0, 1.0)

    # 2. Authority word density
    auth_hits = sum(1 for w in _AUTH_WORDS if w in text_lower)
    auth_norm = min(auth_hits / 4.0, 1.0)

    # 3. Credential harvesting signals
    cred_hits = sum(1 for w in _CREDENTIAL_WORDS if w in text_lower)
    cred_norm = min(cred_hits / 5.0, 1.0)

    # 4. Financial fraud signals
    fin_hits = sum(1 for w in _FINANCIAL_WORDS if w in text_lower)
    fin_norm = min(fin_hits / 4.0, 1.0)

    # 5. Gift card / iTunes / Google Play
    giftcard = 1.0 if re.search(
        r'\b(gift card|itunes|google play|amazon gift|steam)\b', text_lower
    ) else 0.0

    # 6. Secrecy / confidentiality pressure
    secrecy = 1.0 if re.search(
        r'\b(keep (this|it) (secret|confidential|between us)|do not tell|off the record)\b',
        text_lower
    ) else 0.0

    # 7. Fear appeal (account deletion / arrest / lawsuit)
    fear = 1.0 if re.search(
        r'\b(arrest|legal action|lawsuit|permanent(ly)? (banned|suspended|deleted)|'
        r'criminal|prosecute|penalty|fine)\b', text_lower
    ) else 0.0

    # 8. Scarcity
    scarcity = 1.0 if re.search(
        r'\b(only \d+ (left|remaining|seats?|spots?)|limited (time|offer|slots?))\b',
        text_lower
    ) else 0.0

    # 9. Reply-to pressure ("reply ONLY to this email")
    reply_pressure = 1.0 if re.search(
        r'\breply (only |directly )?(to this|using this|via this)\b', text_lower
    ) else 0.0

    # 10. Impersonation keywords combined with target company names
    impersonation = 1.0 if re.search(
        r'\b(paypal|microsoft|apple|amazon|google|netflix|irs|bank of america|'
        r'chase|wells fargo|citibank|dhl|fedex|ups)\b', text_lower
    ) else 0.0

    return [
        urgency_norm, auth_norm, cred_norm, fin_norm, giftcard,
        secrecy, fear, scarcity, reply_pressure, impersonation,
    ]


def _llm_fingerprint_features(body: str, subject: str) -> List[float]:
    """12 LLM-generated-text fingerprint features."""
    text = body.strip()
    words = _RE_WORD.findall(text)
    n_words = max(len(words), 1)
    sentences = [s.strip() for s in _RE_SENTENCE.split(text) if s.strip()]
    n_sent = max(len(sentences), 1)

    # 1. LLM phrase pattern count (normalised)
    llm_phrase_count = sum(
        1 for r in _RE_LLM_PHRASES if r.search(text)
    )
    llm_phrase_norm = min(llm_phrase_count / len(_RE_LLM_PHRASES), 1.0)

    # 2. Personal/informal marker count (inverse LLM signal)
    personal_count = sum(1 for r in _RE_PERSONAL if r.search(text))
    personal_norm  = min(personal_count / len(_RE_PERSONAL), 1.0)

    # 3. Sentence length uniformity (low variance → likely LLM)
    if n_sent > 2:
        sent_lens = [len(_RE_WORD.findall(s)) for s in sentences]
        mean_sl   = sum(sent_lens) / n_sent
        variance  = sum((l - mean_sl)**2 for l in sent_lens) / n_sent
        uniformity = max(0.0, 1.0 - min(variance / 50.0, 1.0))
    else:
        uniformity = 0.5

    # 4. Transition word density (LLM loves "Furthermore", "Moreover"…)
    transition_words = [
        'furthermore', 'moreover', 'additionally', 'consequently',
        'therefore', 'thus', 'hence', 'nonetheless', 'nevertheless',
        'accordingly', 'as a result', 'in conclusion', 'in summary',
        'to summarize', 'in light of', 'with that said',
    ]
    tw_hits = sum(1 for w in transition_words if w in text.lower())
    tw_norm = min(tw_hits / 5.0, 1.0)

    # 5. Passive voice density  (rough: "is/was/were/been + verb-ed")
    passive_matches = re.findall(
        r'\b(is|was|were|been|be|being)\s+\w+ed\b', text, re.I
    )
    passive_ratio = min(len(passive_matches) / max(n_sent, 1) / 0.5, 1.0)

    # 6. Hedging language ("may", "might", "could", "possibly")
    hedging = ['may ', 'might ', 'could ', 'possibly', 'perhaps', 'likely']
    hedge_count = sum(text.lower().count(h) for h in hedging)
    hedge_norm  = min(hedge_count / 5.0, 1.0)

    # 7. Overly polite openers
    polite_open = 1.0 if re.search(
        r'\b(I hope (this email|this message|you are|you\'re) (find|doing|well|'
        r'having|reached))\b', text, re.I
    ) else 0.0

    # 8. Lack of contractions (LLM uses full forms more)
    contractions = re.findall(
        r"\b(I'm|you're|we're|they're|it's|that's|don't|won't|can't|didn't|"
        r"couldn't|wouldn't|shouldn't|isn't|aren't|wasn't|weren't)\b",
        text, re.I
    )
    contraction_density = min(len(contractions) / max(n_words / 20, 1), 1.0)
    no_contraction_signal = 1.0 - contraction_density   # high = fewer contractions

    # 9. Bullet/numbered point overuse (common in LLM instructions)
    bullets = re.findall(r'^\s*[-•*\d]+[.)]\s', text, re.MULTILINE)
    bullet_norm = min(len(bullets) / 10.0, 1.0)

    # 10. Formal closing present
    formal_close = 1.0 if re.search(
        r'\b(sincerely|with (kind|best|warm) regards|yours (faithfully|truly|sincerely))\b',
        text[-300:], re.I
    ) else 0.0

    # 11. Subject formality score
    subject_formal = 1.0 if re.search(
        r'\b(important (notice|update|announcement)|action required|your account|'
        r'security alert|urgent notification)\b',
        subject, re.I
    ) else 0.0

    # 12. Vocabulary richness relative to word count
    #     (LLM texts are often longer but with good vocabulary coverage)
    unique_ratio = len(set(w.lower() for w in words)) / n_words
    rich_vocab   = 1.0 if (unique_ratio > 0.7 and n_words > 80) else 0.0

    return [
        llm_phrase_norm, personal_norm, uniformity, tw_norm, passive_ratio,
        hedge_norm, polite_open, no_contraction_signal, bullet_norm,
        formal_close, subject_formal, rich_vocab,
    ]


def _url_features(urls: List[str], body: str) -> List[float]:
    """8 URL / domain features."""
    n_urls = len(urls)

    # 1. URL count (log-norm)
    url_count_norm = min(math.log1p(n_urls) / math.log(21), 1.0)

    # 2. URL-to-word ratio
    n_words = max(len(_RE_WORD.findall(body)), 1)
    url_word_ratio = min(n_urls / n_words * 10, 1.0)

    # 3. Ratio of URLs with IP addresses
    ip_urls = sum(1 for u in urls if re.search(r'https?://\d+\.\d+\.\d+\.\d+', u))
    ip_ratio = ip_urls / max(n_urls, 1)

    # 4. Ratio of very long URLs (> 100 chars) – obfuscation
    long_urls = sum(1 for u in urls if len(u) > 100)
    long_url_ratio = long_urls / max(n_urls, 1)

    # 5. Ratio of URLs with non-standard TLDs (.xyz .tk .ml .ga .cf .info)
    sus_tld = re.compile(
        r'\.(xyz|tk|ml|ga|cf|info|top|club|online|site|live|click|link|'
        r'download|tech|pw|cc|icu|gq|uno|bid|work)\b',
        re.I
    )
    sus_tld_ratio = sum(1 for u in urls if sus_tld.search(u)) / max(n_urls, 1)

    # 6. URL mismatch with visible anchor text in body
    #    (simplified: check if displayed href != actual href)
    mismatch = 1.0 if re.search(
        r'href="https?://([^"]+)"[^>]*>(?!https?://).*?</a>', body, re.I | re.DOTALL
    ) else 0.0

    # 7. URL shortener presence
    shorteners = re.compile(
        r'(bit\.ly|tinyurl\.com|t\.co|ow\.ly|goo\.gl|short\.to|'
        r'rebrand\.ly|buff\.ly|ift\.tt)', re.I
    )
    has_shortener = 1.0 if any(shorteners.search(u) for u in urls) else 0.0

    # 8. Redirect chain indicator (@-sign in URL)
    has_redirect_symbol = 1.0 if any('@' in u for u in urls) else 0.0

    return [
        url_count_norm, url_word_ratio, ip_ratio, long_url_ratio,
        sus_tld_ratio, mismatch, has_shortener, has_redirect_symbol,
    ]


def _header_features(headers: Dict[str, str], sender: str) -> List[float]:
    """5 email header / authentication features."""
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    auth    = h_lower.get('authentication-results', '')

    # 1. SPF fail
    spf_fail = 1.0 if re.search(r'spf=(fail|softfail|none)', auth) else 0.0

    # 2. DKIM fail
    dkim_fail = 1.0 if re.search(r'dkim=(fail|none)', auth) else 0.0

    # 3. DMARC fail
    dmarc_fail = 1.0 if re.search(r'dmarc=(fail|none)', auth) else 0.0

    # 4. Reply-To differs from From
    reply_to = h_lower.get('reply-to', '')
    from_hdr = h_lower.get('from', sender.lower())
    def _domain(addr: str) -> str:
        m = re.search(r'@([\w.-]+)', addr)
        return m.group(1) if m else ''
    reply_mismatch = 1.0 if (reply_to and _domain(reply_to) != _domain(from_hdr)) else 0.0

    # 5. Suspicious originating IP (known TOR / hosting ranges – heuristic)
    x_ip = h_lower.get('x-originating-ip', '')
    sus_ip = 1.0 if re.match(r'(185\.|194\.|45\.)', x_ip) else 0.0

    return [spf_fail, dkim_fail, dmarc_fail, reply_mismatch, sus_ip]


# ──────────────────────────────────────────────────────────────────────────────
# Build FEATURE_NAMES for inspection / explainability
# ──────────────────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    # Linguistic (15)
    "ling_word_count_norm", "ling_avg_sent_len", "ling_sent_variance",
    "ling_type_token_ratio", "ling_punct_ratio", "ling_digit_ratio",
    "ling_allcaps_ratio", "ling_money_norm", "ling_avg_word_len",
    "ling_fog_index", "ling_has_html", "ling_has_emoji",
    "ling_excl_density", "ling_quest_density", "ling_subj_len",
    # Structural (10)
    "struct_char_count", "struct_blank_ratio", "struct_line_count",
    "struct_has_salutation", "struct_has_closing", "struct_has_unsub",
    "struct_has_disclaimer", "struct_para_count", "struct_short_para_ratio",
    "struct_has_list",
    # Social engineering (10)
    "soc_urgency", "soc_authority", "soc_credential", "soc_financial",
    "soc_giftcard", "soc_secrecy", "soc_fear", "soc_scarcity",
    "soc_reply_pressure", "soc_impersonation",
    # LLM fingerprint (12)
    "llm_phrase_match", "llm_personal_markers", "llm_uniformity",
    "llm_transition_words", "llm_passive_voice", "llm_hedging",
    "llm_polite_open", "llm_no_contractions", "llm_bullets",
    "llm_formal_close", "llm_subject_formal", "llm_rich_vocab",
    # URL (8)
    "url_count", "url_word_ratio", "url_ip_ratio", "url_long_ratio",
    "url_sus_tld", "url_mismatch", "url_shortener", "url_redirect_sym",
    # Header (5)
    "hdr_spf_fail", "hdr_dkim_fail", "hdr_dmarc_fail",
    "hdr_reply_mismatch", "hdr_sus_ip",
]

assert len(FEATURE_NAMES) == 60, f"Expected 60 feature names, got {len(FEATURE_NAMES)}"
