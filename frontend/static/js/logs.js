let currentPage = 1;

const roleIcons   = { employee: '👤', admin: '🔑', outsider: '👾' };
const sourceClass = { rule_engine: 'source-rule', llm: 'source-llm', hybrid: 'source-hybrid', default: 'source-rule' };

function riskColor(s) {
  if (s < 0.4) return 'var(--green)';
  if (s < 0.7) return 'var(--orange)';
  return 'var(--red)';
}

function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function loadLogs(page = 1) {
  currentPage = page;
  const role        = document.getElementById('filterRole').value;
  const label       = document.getElementById('filterLabel').value;
  const flaggedOnly = document.getElementById('flaggedOnly').checked;

  const params = new URLSearchParams({ page, per_page: 25, role, label, flagged_only: flaggedOnly });

  try {
    const resp = await fetch(`/api/logs?${params}`);
    const data = await resp.json();

    renderTable(data.logs);
    renderPagination(data.page, data.total_pages);
    document.getElementById('totalCount').textContent = `${data.total} entries`;
  } catch(e) {
    console.error(e);
  }
}

function renderTable(logs) {
  const tbody = document.getElementById('logsBody');

  if (!logs.length) {
    tbody.innerHTML = `
      <tr><td colspan="8">
        <div class="empty-state"><div class="empty-icon">📋</div>No log entries found</div>
      </td></tr>`;
    return;
  }

  tbody.innerHTML = logs.map(l => {
    const color    = riskColor(l.risk_score);
    const timeStr  = new Date(l.timestamp).toLocaleString();
    const flagDot  = l.flagged ? `<span style="color:var(--red); font-size:10px;">●</span> ` : '';
    const srcClass = sourceClass[l.detection_source] || 'source-llm';

    return `
      <tr style="cursor:pointer;" onclick="showDetail(${l.id})">
        <td style="color:var(--text-muted); font-size:12px;">${flagDot}${l.id}</td>
        <td style="color:var(--text-muted); font-size:12px; white-space:nowrap;">${timeStr}</td>
        <td>${roleIcons[l.user_role] || ''} ${l.user_role}</td>
        <td class="query-cell" title="${escapeHtml(l.query)}">${escapeHtml(l.query)}</td>
        <td><span class="badge badge-${l.label}">${l.label}</span></td>
        <td style="font-family:monospace; font-size:11px; color:var(--text-muted);">${l.attack_type || '—'}</td>
        <td>
          <span style="color:${color}; font-weight:700;">${l.risk_score.toFixed(3)}</span>
          <div class="risk-bar-wrap" style="width:60px; margin-top:3px;">
            <div class="risk-bar" style="width:${(l.risk_score*100).toFixed(0)}%; background:${color};"></div>
          </div>
        </td>
        <td><span class="source-tag ${srcClass}">${l.detection_source || '—'}</span></td>
      </tr>
    `;
  }).join('');
}

function renderPagination(current, total) {
  const container = document.getElementById('pagination');
  if (total <= 1) { container.innerHTML = ''; return; }

  let html = '';

  if (current > 1) html += `<button class="page-btn" onclick="loadLogs(${current-1})">‹ Prev</button>`;

  const start = Math.max(1, current - 2);
  const end   = Math.min(total, current + 2);

  if (start > 1) html += `<button class="page-btn" onclick="loadLogs(1)">1</button>${start > 2 ? '<span style="color:var(--text-muted);padding:0 4px;">…</span>' : ''}`;

  for (let i = start; i <= end; i++) {
    html += `<button class="page-btn ${i === current ? 'active' : ''}" onclick="loadLogs(${i})">${i}</button>`;
  }

  if (end < total) html += `${end < total-1 ? '<span style="color:var(--text-muted);padding:0 4px;">…</span>' : ''}<button class="page-btn" onclick="loadLogs(${total})">${total}</button>`;

  if (current < total) html += `<button class="page-btn" onclick="loadLogs(${current+1})">Next ›</button>`;

  container.innerHTML = html;
}

async function showDetail(id) {
  try {
    const resp = await fetch(`/api/logs/${id}`);
    const l = await resp.json();

    const color = riskColor(l.risk_score);
    const timeStr = new Date(l.timestamp).toLocaleString();

    document.getElementById('modalContent').innerHTML = `
      <div style="margin-bottom:20px;">
        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
          <span class="badge badge-${l.label}" style="font-size:13px; padding:5px 14px;">${l.label.toUpperCase()}</span>
          <span style="font-size:28px; font-weight:700; color:${color};">${l.risk_score.toFixed(3)}</span>
        </div>
      </div>

      <div style="margin-bottom:16px;">
        <div class="form-label">SQL Query</div>
        <pre style="background:var(--surface2); border:1px solid var(--border); border-radius:6px; padding:14px; font-size:12px; overflow-x:auto; white-space:pre-wrap; color:var(--text);">${escapeHtml(l.query)}</pre>
      </div>

      <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px;">
        <div>
          <div class="form-label">Role</div>
          <div>${roleIcons[l.user_role] || ''} ${l.user_role}</div>
        </div>
        <div>
          <div class="form-label">Attack Type</div>
          <div style="font-family:monospace;">${l.attack_type || 'none'}</div>
        </div>
        <div>
          <div class="form-label">Detection Source</div>
          <span class="source-tag ${sourceClass[l.detection_source] || ''}">${l.detection_source}</span>
        </div>
        <div>
          <div class="form-label">Role Multiplier</div>
          <div>×${l.role_multiplier}</div>
        </div>
        <div>
          <div class="form-label">Flagged</div>
          <div>${l.flagged ? '<span style="color:var(--red);">⚠ YES</span>' : '<span style="color:var(--green);">✓ NO</span>'}</div>
        </div>
        <div>
          <div class="form-label">Timestamp</div>
          <div style="color:var(--text-muted); font-size:12px;">${timeStr}</div>
        </div>
      </div>

      <div>
        <div class="form-label">Explanation</div>
        <div style="background:var(--surface2); border-radius:6px; padding:12px; font-size:13px; line-height:1.6; color:var(--text);">
          ${escapeHtml(l.explanation || 'No explanation available')}
        </div>
      </div>
    `;

    document.getElementById('modal').style.display = 'block';
  } catch(e) {
    console.error(e);
  }
}

function closeModal() {
  document.getElementById('modal').style.display = 'none';
}

// Close on backdrop click
document.getElementById('modal')?.addEventListener('click', function(e) {
  if (e.target === this) closeModal();
});

document.addEventListener('DOMContentLoaded', () => loadLogs(1));