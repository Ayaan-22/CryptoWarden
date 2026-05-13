// ─── State ───
let socket = null;
let startTime = Date.now();
let eventCount = 0;
let alertCount = 0;
let typeCounts = { modified: 0, created: 0, deleted: 0, moved: 0 };
let epmHistory = [];      // { time, value } — events per minute over time
let epmBucketCount = 0;   // events in current 10s bucket

// ─── DOM References ───
const $ = (id) => document.getElementById(id);
const statusBadge = $('connectionBadge');
const statusText = $('connectionText');
const scannedCount = $('scannedCount');
const blockedCount = $('blockedCount');
const healthStatus = $('healthStatus');
const uptimeEl = $('uptimeValue');
const eventsPerMin = $('eventsPerMin');
const feedContent = $('feedContent');
const alertsContent = $('alertsContent');
const alertCounter = $('alertCounter');
const alertCounterOverview = $('alertCounterOverview');
const overviewAlerts = $('overviewAlerts');
const clockEl = $('navClock');

// ─── Chart.js Config ───
Chart.defaults.color = '#475569';
Chart.defaults.borderColor = 'rgba(56, 189, 248, 0.06)';
Chart.defaults.font.family = "'JetBrains Mono', monospace";
Chart.defaults.font.size = 10;

// Events Per Minute — Line Chart
const epmCtx = $('epmChart').getContext('2d');
const epmGradient = epmCtx.createLinearGradient(0, 0, 0, 200);
epmGradient.addColorStop(0, 'rgba(34, 211, 238, 0.2)');
epmGradient.addColorStop(1, 'rgba(34, 211, 238, 0.0)');

const epmChart = new Chart(epmCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Events/min',
            data: [],
            borderColor: '#22d3ee',
            backgroundColor: epmGradient,
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHitRadius: 8,
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        plugins: { legend: { display: false } },
        scales: {
            x: { display: true, grid: { display: false }, ticks: { maxTicksLimit: 8 } },
            y: { display: true, beginAtZero: true, grid: { color: 'rgba(56, 189, 248, 0.04)' } }
        }
    }
});

// Event Type — Doughnut Chart
const typeChart = new Chart($('typeChart').getContext('2d'), {
    type: 'doughnut',
    data: {
        labels: ['Modified', 'Created', 'Deleted', 'Moved'],
        datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: [
                'rgba(59, 130, 246, 0.7)',
                'rgba(16, 185, 129, 0.7)',
                'rgba(239, 68, 68, 0.7)',
                'rgba(245, 158, 11, 0.7)'
            ],
            borderColor: [
                'rgba(59, 130, 246, 1)',
                'rgba(16, 185, 129, 1)',
                'rgba(239, 68, 68, 1)',
                'rgba(245, 158, 11, 1)'
            ],
            borderWidth: 1,
            hoverOffset: 6,
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        animation: { duration: 400 },
        plugins: {
            legend: {
                position: 'right',
                labels: { padding: 12, usePointStyle: true, pointStyleWidth: 8 }
            }
        }
    }
});

// ─── Clock ───
function updateClock() {
    clockEl.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ─── Uptime ───
function updateUptime() {
    const diff = Math.floor((Date.now() - startTime) / 1000);
    const h = String(Math.floor(diff / 3600)).padStart(2, '0');
    const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
    const s = String(diff % 60).padStart(2, '0');
    uptimeEl.textContent = `${h}:${m}:${s}`;
}
setInterval(updateUptime, 1000);

// ─── EPM Chart Update (every 10s) ───
setInterval(() => {
    const rate = epmBucketCount * 6; // scale 10s bucket to per-minute
    const label = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    epmChart.data.labels.push(label);
    epmChart.data.datasets[0].data.push(rate);

    // Keep last 30 data points (5 minutes of history)
    if (epmChart.data.labels.length > 30) {
        epmChart.data.labels.shift();
        epmChart.data.datasets[0].data.shift();
    }
    epmChart.update('none'); // no animation for smooth scrolling

    eventsPerMin.textContent = rate;
    epmBucketCount = 0;
}, 10000);

// ─── Tab Switching ───
window.switchTab = function(tabId) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    $('tab-' + tabId).classList.add('active');
    event.target.classList.add('active');
};

// ─── WebSocket ───
function connect() {
    socket = new WebSocket('ws://127.0.0.1:8001/ws');

    socket.onopen = () => {
        statusBadge.classList.add('connected');
        statusText.textContent = 'Online';
        startTime = Date.now();
        eventCount = 0;
    };

    socket.onclose = () => {
        statusBadge.classList.remove('connected');
        statusText.textContent = 'Offline';
        setTimeout(connect, 3000);
    };

    socket.onerror = () => {
        statusBadge.classList.remove('connected');
        statusText.textContent = 'Error';
    };

    socket.onmessage = (event) => {
        try {
            handleMessage(JSON.parse(event.data));
        } catch (e) {
            console.error('Parse error:', e);
        }
    };
}

function handleMessage(msg) {
    if (msg.type === 'activity') {
        addFeedItem(msg.data);
        eventCount++;
        epmBucketCount++;
        // Update type chart
        const t = msg.data.type;
        if (typeCounts[t] !== undefined) {
            typeCounts[t]++;
            typeChart.data.datasets[0].data = [typeCounts.modified, typeCounts.created, typeCounts.deleted, typeCounts.moved];
            typeChart.update('none');
        }
    } else if (msg.type === 'alert') {
        addAlert(msg.data);
    } else if (msg.type === 'stats') {
        animateCounter(scannedCount, msg.data.scanned);
        animateCounter(blockedCount, msg.data.blocked);
        healthStatus.textContent = msg.data.blocked > 0 ? 'Threat' : 'Secure';
        healthStatus.style.color = msg.data.blocked > 0 ? 'var(--accent-amber)' : 'var(--accent-green)';
    }
}

// ─── Counter Animation ───
function animateCounter(el, target) {
    const current = parseInt(el.textContent) || 0;
    if (current === target) return;
    const step = target > current ? 1 : -1;
    let val = current;
    const interval = setInterval(() => {
        val += step;
        el.textContent = val;
        if (val === target) clearInterval(interval);
    }, 30);
}

// ─── Feed ───
function addFeedItem(data) {
    const empty = feedContent.querySelector('.panel-empty');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = 'feed-item';
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const shortPath = data.src_path ? data.src_path.split('\\').slice(-2).join('\\') : 'unknown';

    item.innerHTML = `
        <span class="feed-time">${time}</span>
        <span class="feed-badge ${data.type}">${data.type}</span>
        <span class="feed-path" title="${data.src_path || ''}">${shortPath}</span>
        <span class="feed-pid">${data.pid ? 'PID ' + data.pid : '—'}</span>
    `;

    feedContent.insertBefore(item, feedContent.firstChild);
    if (feedContent.children.length > 200) feedContent.removeChild(feedContent.lastChild);
}

// ─── Alerts ───
function addAlert(data) {
    alertCount++;

    // Update counters
    alertCounter.textContent = alertCount;
    alertCounter.style.display = 'inline-flex';
    alertCounterOverview.textContent = alertCount;
    alertCounterOverview.style.display = 'inline-flex';

    // Build alert element
    const alertEl = buildAlertElement(data);

    // Add to Threats tab
    const emptyThreats = alertsContent.querySelector('.panel-empty');
    if (emptyThreats) emptyThreats.remove();
    alertsContent.insertBefore(alertEl, alertsContent.firstChild);

    // Add clone to Overview tab
    const emptyOverview = overviewAlerts.querySelector('.panel-empty');
    if (emptyOverview) emptyOverview.remove();
    overviewAlerts.insertBefore(alertEl.cloneNode(true), overviewAlerts.firstChild);
    // Keep overview compact
    while (overviewAlerts.children.length > 3) overviewAlerts.removeChild(overviewAlerts.lastChild);

    // Flash the threats tab button
    const threatBtn = document.querySelectorAll('.tab-btn')[2];
    threatBtn.style.color = 'var(--accent-red)';
    setTimeout(() => { if (!threatBtn.classList.contains('active')) threatBtn.style.color = ''; }, 2000);
}

function buildAlertElement(data) {
    const el = document.createElement('div');
    el.className = 'alert-item';
    el.innerHTML = `
        <div class="alert-severity">
            <span class="pulse-ring"></span>
            Critical — Ransomware Detected
        </div>
        <div class="alert-detail">
            <strong>${data.name || 'Unknown'}</strong> (PID: ${data.pid || '?'})<br>
            ${data.reason || 'Suspicious behavior detected'}
        </div>
        <div class="alert-actions">
            <button class="btn btn-danger" onclick="sendCommand('kill', ${data.pid})">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:-2px;margin-right:4px"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                Terminate
            </button>
            <button class="btn btn-success" onclick="sendCommand('whitelist', null, '${data.name}')">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:-2px;margin-right:4px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                Whitelist
            </button>
        </div>
    `;
    return el;
}

// ─── Commands ───
function sendCommand(command, pid = null, processName = null) {
    const payload = { command };
    if (pid) payload.pid = pid;
    if (processName) payload.process_name = processName;

    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify(payload));
    }

    if (command === 'kill') {
        const alerts = alertsContent.querySelectorAll('.alert-item');
        for (const a of alerts) {
            if (a.innerHTML.includes(`PID: ${pid}`)) {
                a.style.opacity = '0.3';
                a.style.pointerEvents = 'none';
                a.style.transform = 'scale(0.97)';
                setTimeout(() => a.remove(), 600);
                break;
            }
        }
    }
}

function clearFeed() {
    feedContent.innerHTML = `
        <div class="panel-empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
            Feed cleared. Waiting for new events...
        </div>`;
}

function clearAlerts() {
    alertCount = 0;
    alertCounter.style.display = 'none';
    alertCounterOverview.style.display = 'none';
    alertsContent.innerHTML = `
        <div class="panel-empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            No active threats. System is clean.
        </div>`;
}

// ─── Boot ───
connect();
