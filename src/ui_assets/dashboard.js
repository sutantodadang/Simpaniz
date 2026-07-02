// Simpaniz Metrics Dashboard — hand-rolled canvas line charts, no
// dependencies. Talks to /_dashboard/api/* using the same SigV4-signed
// fetch app.js already built for the S3 API (exposed as
// window.simpanizApiGet).
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const state = {
    windowS: 3600,
    timer: 0,
    active: false,
  };

  // ── Formatting ────────────────────────────────────────────────────────
  function fmtUptime(s) {
    s = Math.max(0, s || 0);
    const d = Math.floor(s / 86400); s -= d * 86400;
    const h = Math.floor(s / 3600); s -= h * 3600;
    const m = Math.floor(s / 60);
    const parts = [];
    if (d) parts.push(`${d}d`);
    if (d || h) parts.push(`${h}h`);
    parts.push(`${m}m`);
    return parts.join(' ');
  }

  function fmtNum(v) {
    if (!Number.isFinite(v)) return '0';
    if (Math.abs(v) >= 1000) return (v / 1000).toFixed(1) + 'k';
    return Number.isInteger(v) ? String(v) : v.toFixed(1);
  }

  // ── Canvas line chart ────────────────────────────────────────────────
  // series: [{ label, color, values: number[] }] sharing one x-axis.
  // Draws axes, polylines, and min/max y labels only — no hover tooltip
  // (ponytail: skipped, fiddly for little payoff on a small dashboard).
  function drawChart(canvas, series) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 400;
    const h = canvas.clientHeight || 160;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const padL = 44, padR = 10, padT = 10, padB = 18;
    const plotW = Math.max(1, w - padL - padR);
    const plotH = Math.max(1, h - padT - padB);

    const allValues = series.flatMap((s) => s.values).filter((v) => Number.isFinite(v));
    let max = allValues.length ? Math.max(...allValues) : 1;
    let min = allValues.length ? Math.min(0, ...allValues) : 0;
    if (max === min) max = min + 1;

    // Axes.
    ctx.strokeStyle = '#262c38';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padL, padT);
    ctx.lineTo(padL, padT + plotH);
    ctx.lineTo(padL + plotW, padT + plotH);
    ctx.stroke();

    // Y-axis min/max labels.
    ctx.fillStyle = '#8a93a6';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(fmtNum(max), padL - 6, padT + 8);
    ctx.fillText(fmtNum(min), padL - 6, padT + plotH);

    const n = Math.max(1, ...series.map((s) => s.values.length));
    const xStep = n > 1 ? plotW / (n - 1) : 0;
    const yFor = (v) => padT + plotH - ((v - min) / (max - min)) * plotH;

    for (const s of series) {
      if (!s.values.length) continue;
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      s.values.forEach((v, i) => {
        const x = padL + i * xStep;
        const y = yFor(Number.isFinite(v) ? v : 0);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
  }

  function legend(container, series) {
    if (!container) return;
    container.innerHTML = series
      .map((s) => `<span class="legend-item"><span class="dot" style="background:${s.color}"></span>${s.label}</span>`)
      .join('');
  }

  // ── Rendering ─────────────────────────────────────────────────────────
  function renderSummary(sum) {
    const tls = sum.tls ? '<span class="badge ok">TLS</span>' : '<span class="badge">no TLS</span>';
    const errPct = sum.requests_total > 0 ? ((100 * sum.errors_total) / sum.requests_total).toFixed(2) : '0.00';

    let clusterCard = '';
    if (sum.cluster && Array.isArray(sum.membership)) {
      const dots = sum.membership
        .map((n) => {
          const cls = n.state === 'alive' ? 'ok' : n.state === 'suspect' ? 'warn' : 'err';
          return `<span class="node-dot ${cls}" title="${n.id}: ${n.state}"></span>`;
        })
        .join('');
      clusterCard = `<div class="card"><div class="card-label">Cluster nodes</div><div class="card-value nodes">${dots}</div></div>`;
    }

    $('metrics-cards').innerHTML = `
      <div class="card"><div class="card-label">Uptime</div><div class="card-value">${fmtUptime(sum.uptime_s)}</div></div>
      <div class="card"><div class="card-label">Requests</div><div class="card-value">${fmtNum(sum.requests_total || 0)}</div></div>
      <div class="card"><div class="card-label">Error rate</div><div class="card-value">${errPct}%</div></div>
      <div class="card"><div class="card-label">In-flight</div><div class="card-value">${sum.in_flight ?? 0}</div></div>
      <div class="card"><div class="card-label">IAM users</div><div class="card-value">${sum.iam_users ?? 0}</div></div>
      <div class="card"><div class="card-label">Mode</div><div class="card-value">${sum.mode ?? ''} ${tls}</div></div>
      ${clusterCard}
    `;
  }

  function renderSeries(series) {
    const pts = series.points || [];

    drawChart($('chart-reqs'), [
      { label: 'req/s', color: '#4f8cff', values: pts.map((p) => p.rps) },
      { label: 'err/s', color: '#e2574c', values: pts.map((p) => p.eps) },
    ]);
    legend($('legend-reqs'), [{ label: 'req/s', color: '#4f8cff' }, { label: 'err/s', color: '#e2574c' }]);

    drawChart($('chart-latency'), [
      { label: 'p50', color: '#2ec27e', values: pts.map((p) => p.p50) },
      { label: 'p95', color: '#e0a72e', values: pts.map((p) => p.p95) },
      { label: 'p99', color: '#e2574c', values: pts.map((p) => p.p99) },
    ]);
    legend($('legend-latency'), [
      { label: 'p50', color: '#2ec27e' },
      { label: 'p95', color: '#e0a72e' },
      { label: 'p99', color: '#e2574c' },
    ]);

    drawChart($('chart-throughput'), [
      { label: 'in B/s', color: '#4f8cff', values: pts.map((p) => p.in_bps) },
      { label: 'out B/s', color: '#2ec27e', values: pts.map((p) => p.out_bps) },
    ]);
    legend($('legend-throughput'), [{ label: 'in B/s', color: '#4f8cff' }, { label: 'out B/s', color: '#2ec27e' }]);

    drawChart($('chart-inflight'), [{ label: 'in-flight', color: '#4f8cff', values: pts.map((p) => p.inflight) }]);
    legend($('legend-inflight'), [{ label: 'in-flight', color: '#4f8cff' }]);
  }

  // ── Polling ──────────────────────────────────────────────────────────
  async function refresh() {
    if (!state.active || !window.simpanizApiGet) return;
    try {
      const [summary, series] = await Promise.all([
        window.simpanizApiGet('/_dashboard/api/summary'),
        window.simpanizApiGet('/_dashboard/api/series', `window=${state.windowS}`),
      ]);
      renderSummary(summary);
      renderSeries(series);
    } catch (e) {
      console.error('metrics refresh failed', e);
    }
  }

  function start() {
    state.active = true;
    refresh();
    clearInterval(state.timer);
    state.timer = setInterval(refresh, 10000);
  }

  function stop() {
    state.active = false;
    clearInterval(state.timer);
  }

  // ── Wire up ───────────────────────────────────────────────────────────
  function init() {
    document.querySelectorAll('.win-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.win-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.windowS = parseInt(btn.dataset.window, 10) || 3600;
        refresh();
      });
    });

    document.addEventListener('simpaniz:tab', (e) => {
      if (e.detail.tab === 'metrics') start(); else stop();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
