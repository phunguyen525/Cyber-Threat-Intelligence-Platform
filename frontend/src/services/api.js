const API_BASE = "http://127.0.0.1:8000";

export async function fetchHealth() {
    const res = await fetch(`${API_BASE}/health`);
    return res.json();
}

export async function fetchThreats() {
    const res = await fetch(`${API_BASE}/threats`);
    return res.json();
}

export async function fetchSuspiciousIPs() {
    const res = await fetch(`${API_BASE}/ips/suspicious`);
    return res.json();
}

export async function fetchRecentEvents(limit = 20) {
    const res = await fetch(`${API_BASE}/events/recent?limit=${limit}`);
    return res.json();
}

export async function fetchGraph() {
    const res = await fetch(`${API_BASE}/graph`);
    return res.json();
}