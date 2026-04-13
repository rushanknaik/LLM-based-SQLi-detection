// ── State ──────────────────────────────────────────────
let selectedRole = 'employee';
const sessionId = crypto.randomUUID();
const sessionStats = { total: 0, attacks: 0, riskSum: 0 };

// ── Role Selection ─────────────────────────────────────
function selectRole(role) {
  selectedRole = role;
  document.querySelectorAll('.role-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`[data-role="${role}"]`).classList.add('active');
}

// ── Load Sample Query ──────────────────────────────────
function loadSample(el) {
  // Get text content, strip the tag span text
  const clone = el.cloneNode(true);
  clone.querySelector('.sample-tag')?.remove();
  const text = clone.textContent.trim();
  document.getElementById('queryInput').value = text;
  document.getElementById('queryInput').focus();
}

// ── Clear ──────────────────────────────────────────────
function clearAll() {
  document.getElementById('queryInput').value = '';
  document.getElementById('resultPanel').className = 'result-panel mt-16';
  document.getElementById('loadingPanel').style.display = 'none';
}

// ── Risk Color ─────────────────────────────────────────
function riskColor(score) {
  if (score < 0.4) return 'var(--green)';
  if (score < 0.7) return 'var(--orange)';
  return 'var(--red)';
}

// ── Render Result ──────────────────────────────────────
function renderResult(data) {
  const r = data.result;
  const panel = document.getElementById('resultPanel');

  // Panel color class
  panel.className = `result-panel mt-16 show ${r.label}`;

  // Badge
  const badge = document.getElementById('resultBadge');
  const icons = { benign: '✅', sqli: '🔴', insider: '🟠' };
  badge.className = `badge badge-${r.label}`;
  badge.textContent = `${icons[r.label]} ${r.label.toUpperCase()}`;

  // Risk score
  const color = riskColor(r.risk_score);
  document.getElementById('riskScoreDisplay').style.color = color;
  document.getElementById('riskScoreDisplay').textContent = r.risk_score.toFixed(3);

  // Risk bar
  const bar = document.getElementById('riskBar');
  bar.style.width = `${(r.risk_score * 100).toFixed(1)}%`;
  bar.style.background = color;

  // Meta fields
  document.getElementById('attackType').textContent = r.attack_type || 'none';

  const srcMap = {
    rule_engine: '<span class="source-tag source-rule">rule engine</span>',
    llm:         '<span class="source-tag source-llm">LLM</span>',
    hybrid:      '<span class="source-tag source-hybrid">hybrid</span>',
    default:     '<span class="source-tag source-rule">default</span>',
  };
  document.getElementById('detectionSource').innerHTML = srcMap[r.detection_source] || r.detection_source;
  document.getElementById('roleMultiplier').textContent = `×${r.role_multiplier} (${selectedRole})`;
  document.getElementById('explanation').textContent = r.explanation;
}

// ── Update Session Stats ───────────────────────────────
function updateSessionStats(result) {
  sessionStats.total++;
  if (result.label !== 'benign') sessionStats.attacks++;
  sessionStats.riskSum += result.risk_score;

  document.getElementById('sessionTotal').textContent = sessionStats.total;
  document.getElementById('sessionAttacks').textContent = sessionStats.attacks;
  document.getElementById('sessionAvgRisk').textContent =
    (sessionStats.riskSum / sessionStats.total).toFixed(2);
}

// ── Show Toast ─────────────────────────────────────────
function showToast(msg, color = 'var(--text)') {
  const t = document.createElement('div');
  t.className = 'toast';
  t.style.color = color;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

// ── Main: Analyze Query ────────────────────────────────
async function analyzeQuery() {
  const query = document.getElementById('queryInput').value.trim();
  if (!query) { showToast('Please enter a SQL query.', 'var(--orange)'); return; }

  // Show loading
  document.getElementById('resultPanel').className = 'result-panel mt-16';
  document.getElementById('loadingPanel').style.display = 'block';
  const btn = document.getElementById('analyzeBtn');
  btn.disabled = true;

  // Simulate LLM thinking messages
  const loadingTexts = [
    'Running rule engine...',
    'Calling LLM classifier...',
    'Aggregating risk score...',
    'Finalizing result...'
  ];
  let ltIdx = 0;
  const ltInterval = setInterval(() => {
    document.getElementById('loadingText').textContent = loadingTexts[ltIdx % loadingTexts.length];
    ltIdx++;
  }, 900);

  try {
    const resp = await fetch('/api/query/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query,
        user_role: selectedRole,
        session_id: sessionId,
      })
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.detail || 'API error');
    }

    const data = await resp.json();
    renderResult(data);
    updateSessionStats(data.result);

    if (data.result.flagged) {
      showToast(`⚠️ Threat detected: ${data.result.label.toUpperCase()}`, riskColor(data.result.risk_score));
    }

  } catch (e) {
    showToast(`Error: ${e.message}`, 'var(--red)');
    console.error(e);
  } finally {
    clearInterval(ltInterval);
    document.getElementById('loadingPanel').style.display = 'none';
    btn.disabled = false;
  }
}

// ── Enter key submits ──────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('queryInput').addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter') analyzeQuery();
  });
});