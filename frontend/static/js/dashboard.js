// ── Chart instances ────────────────────────────────────
let timelineChart = null;
let donutChart = null;

const COLORS = {
  benign:  '#3fb950',
  sqli:    '#f85149',
  insider: '#d29922',
};

// ── Load Stats Cards ───────────────────────────────────
async function loadStats() {
  const data = await fetchJSON('/api/dashboard/stats');
  document.getElementById('totalQueries').textContent = data.total_queries ?? 0;
  document.getElementById('benignCount').textContent  = data.benign_count ?? 0;
  document.getElementById('sqliCount').textContent    = data.sqli_count ?? 0;
  document.getElementById('insiderCount').textContent = data.insider_count ?? 0;
  document.getElementById('avgRisk').textContent      = (data.avg_risk_score ?? 0).toFixed(3);
}

// ── Timeline Chart ─────────────────────────────────────
async function loadTimeline() {
  const rows = await fetchJSON('/api/dashboard/timeline');

  const labels  = rows.map(r => r.hour);
  const sqli    = rows.map(r => r.sqli);
  const insider = rows.map(r => r.insider);
  const benign  = rows.map(r => r.benign);

  const ctx = document.getElementById('timelineChart').getContext('2d');

  if (timelineChart) timelineChart.destroy();

  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'SQL Injection',
          data: sqli,
          borderColor: COLORS.sqli,
          backgroundColor: 'rgba(248,81,73,0.1)',
          tension: 0.4,
          fill: true,
          pointRadius: 3,
        },
        {
          label: 'Insider Threat',
          data: insider,
          borderColor: COLORS.insider,
          backgroundColor: 'rgba(210,153,34,0.1)',
          tension: 0.4,
          fill: true,
          pointRadius: 3,
        },
        {
          label: 'Benign',
          data: benign,
          borderColor: COLORS.benign,
          backgroundColor: 'rgba(63,185,80,0.05)',
          tension: 0.4,
          fill: true,
          pointRadius: 3,
        },
      ]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { labels: { color: '#8b949e', font: { size: 11 } } }
      },
      scales: {
        x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: '#21262d' }, beginAtZero: true },
      }
    }
  });
}

// ── Donut Chart ────────────────────────────────────────
async function loadDonut() {
  const rows = await fetchJSON('/api/dashboard/threat-distribution');

  const labelMap = { benign: 'Benign', sqli: 'SQL Injection', insider: 'Insider Threat' };
  const labels = rows.map(r => labelMap[r.label] || r.label);
  const data   = rows.map(r => r.count);
  const colors = rows.map(r => COLORS[r.label] || '#58a6ff');

  const ctx = document.getElementById('donutChart').getContext('2d');
  if (donutChart) donutChart.destroy();

  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }]
    },
    options: {
      responsive: true,
      cutout: '68%',
      plugins: {
        legend: { position: 'bottom', labels: { color: '#8b949e', font: { size: 11 }, padding: 12 } }
      }
    }
  });
}

// ── Role Stats Table ───────────────────────────────────
async function loadRoleStats() {
  const rows = await fetchJSON('/api/dashboard/role-stats');
  const tbody = document.getElementById('roleStatsBody');

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No data yet</td></tr>`;
    return;
  }

  const roleIcons = { employee: '👤', admin: '🔑', outsider: '👾' };

  tbody.innerHTML = rows.map(r => {
    const rate = r.total ? ((r.attacks / r.total) * 100).toFixed(0) : 0;
    const riskColor = r.avg_risk < 0.4 ? 'var(--green)' : r.avg_risk < 0.7 ? 'var(--orange)' : 'var(--red)';
    return `
      <tr>
        <td>${roleIcons[r.user_role] || ''} ${r.user_role}</td>
        <td>${r.total}</td>
        <td>${r.attacks}</td>
        <td style="color:${riskColor}; font-weight:600;">${r.avg_risk.toFixed(3)}</td>
        <td>
          <div style="display:flex; align-items:center; gap:8px;">
            <div style="flex:1; background:var(--surface2); border-radius:3px; height:5px; overflow:hidden;">
              <div style="width:${rate}%; height:100%; background:${riskColor};"></div>
            </div>
            <span style="font-size:11px; min-width:28px;">${rate}%</span>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

// ── Alert Feed ─────────────────────────────────────────
async function loadAlertFeed() {
  const rows = await fetchJSON('/api/dashboard/recent-flags');
  const feed = document.getElementById('alertFeed');

  if (!rows.length) {
    feed.innerHTML = `<div class="empty-state"><div class="empty-icon">✅</div>No threats flagged yet</div>`;
    return;
  }

  const roleIcons = { employee: '👤', admin: '🔑', outsider: '👾' };

  feed.innerHTML = rows.map(r => {
    const color = r.risk_score >= 0.8 ? 'var(--red)' : 'var(--orange)';
    const timeStr = new Date(r.timestamp).toLocaleTimeString();
    return `
      <div class="alert-item ${r.label}">
        <span style="font-size:11px; color:var(--text-muted); min-width:48px;">${timeStr}</span>
        <span style="min-width:20px;">${roleIcons[r.user_role] || ''}</span>
        <span class="alert-query">${escapeHtml(r.query)}</span>
        <span class="badge badge-${r.label}" style="font-size:10px; padding:2px 7px;">${r.label}</span>
        <span class="alert-score" style="color:${color};">${r.risk_score.toFixed(2)}</span>
      </div>
    `;
  }).join('');
}

// ── Heatmap ────────────────────────────────────────────
async function loadHeatmap() {
  const rows = await fetchJSON('/api/dashboard/heatmap');
  const container = document.getElementById('heatmapContainer');

  if (!rows.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">📊</div>No attack data yet</div>`;
    return;
  }

  // Build matrix
  const roles       = [...new Set(rows.map(r => r.user_role))];
  const attackTypes = [...new Set(rows.map(r => r.attack_type))];
  const maxCount    = Math.max(...rows.map(r => r.count));

  const matrix = {};
  rows.forEach(r => {
    if (!matrix[r.user_role]) matrix[r.user_role] = {};
    matrix[r.user_role][r.attack_type] = r.count;
  });

  function heatColor(count) {
    if (!count) return 'rgba(255,255,255,0.03)';
    const intensity = count / maxCount;
    const r = Math.round(248 * intensity);
    const g = Math.round(81 * (1 - intensity));
    return `rgba(${r}, ${g}, 73, ${0.2 + intensity * 0.7})`;
  }

  const roleIcons = { employee: '👤', admin: '🔑', outsider: '👾' };

  const html = `
    <div style="overflow-x:auto;">
      <table class="heatmap-table" style="width:100%; border-collapse:collapse;">
        <thead>
          <tr>
            <th style="text-align:left; padding:8px 12px; color:var(--text-muted); font-size:11px;">Role</th>
            ${attackTypes.map(at =>
              `<th style="color:var(--text-muted); font-size:10px; white-space:nowrap; padding:8px 6px;">
                ${at.replace(/_/g, ' ')}
              </th>`
            ).join('')}
          </tr>
        </thead>
        <tbody>
          ${roles.map(role => `
            <tr>
              <td style="padding:8px 12px; font-weight:600; white-space:nowrap;">
                ${roleIcons[role] || ''} ${role}
              </td>
              ${attackTypes.map(at => {
                const count = matrix[role]?.[at] || 0;
                const bg = heatColor(count);
                return `<td style="text-align:center; padding:4px;">
                  <div class="heat-cell" style="background:${bg}; color:var(--text);">
                    ${count || '–'}
                  </div>
                </td>`;
              }).join('')}
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;

  container.innerHTML = html;
}

// ── Helpers ────────────────────────────────────────────
async function fetchJSON(url) {
  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } catch (e) {
    console.error(`fetchJSON(${url}) error:`, e);
    return [];
  }
}

function escapeHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Load All ───────────────────────────────────────────
async function loadAll() {
  const btn = document.getElementById('refreshBtn');
  btn.textContent = '↻ Refreshing...';
  btn.disabled = true;

  await Promise.all([
    loadStats(),
    loadTimeline(),
    loadDonut(),
    loadRoleStats(),
    loadAlertFeed(),
    loadHeatmap(),
  ]);

  btn.textContent = '↻ Refresh';
  btn.disabled = false;
}

// ── Init ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadAll();
  // Auto-refresh every 30 seconds
  setInterval(loadAll, 30000);
});