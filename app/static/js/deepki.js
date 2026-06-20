/**
 * (●°u°●)​ 」 DeepKi Frontend Scripts
 * Xiao Qi's client-side helpers~
 */

// ── Terminal-style scan log (for the cute console feel) ──
class ScanTerminal {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.lines = [];
    }

    log(msg, type = '') {
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = msg;
        this.container.appendChild(line);
        this.container.scrollTop = this.container.scrollHeight;
        this.lines.push(msg);
    }

    clear() {
        this.container.innerHTML = '';
        this.lines = [];
    }
}

// ── WebSocket handler for scan progress ──
class ScanWSHandler {
    constructor(scanId, onMessage) {
        this.scanId = scanId;
        this.onMessage = onMessage;
        this.ws = null;
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/scan/${this.scanId}`;
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('(●°u°●)​ 」 WebSocket connected');
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (this.onMessage) {
                this.onMessage(data);
            }
        };

        this.ws.onclose = () => {
            console.log('^ - ^ WebSocket closed');
        };

        this.ws.onerror = (err) => {
            console.error('T^T WebSocket error:', err);
        };
    }

    // Send heartbeat ping
    startPing(intervalMs = 15000) {
        this._pingInterval = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send('ping');
            }
        }, intervalMs);
    }

    disconnect() {
        if (this._pingInterval) clearInterval(this._pingInterval);
        if (this.ws) this.ws.close();
    }
}

// ── Copy to clipboard ──
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show brief toast
        const toast = document.createElement('div');
        toast.className = 'toast toast-success';
        toast.innerHTML = '<span>~_^ Copied!</span>';
        document.getElementById('toast-container').appendChild(toast);
        setTimeout(() => toast.remove(), 2000);
    }).catch(() => {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    });
}

// ── Form validation ──
document.addEventListener('htmx:beforeRequest', function(evt) {
    // Show loading state
    const btn = evt.target.querySelector('button[type="submit"]');
    if (btn) {
        btn.disabled = true;
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = '>_< Working...';
    }
});

document.addEventListener('htmx:afterRequest', function(evt) {
    // Restore button
    const btn = evt.target.querySelector('button[type="submit"]');
    if (btn && btn.dataset.originalText) {
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalText;
    }
});

// ── Smooth scroll for new content ──
document.addEventListener('htmx:afterSettle', function(evt) {
    if (evt.target.id === 'scan-result') {
        document.getElementById('scan-result').scrollIntoView({
            behavior: 'smooth',
            block: 'start',
        });
    }
});

console.log('(●°u°●)​ 」 DeepKi frontend loaded~ Ready to scan!');
