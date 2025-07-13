const abuseKey = "655143d3513013ea5c3d921346ec4d144ad2573e55a053f0d29b7abfba95b98d3f9251969147d81c";

const categoryMap = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
};




export async function lookupAbuseIPDB(ip, container) {
    try {
        const res = await chrome.runtime.sendMessage({
            action: "fetchAbuseIPDB",
            ip,
            apiKey: abuseKey
        });

        if (res.error) throw new Error(res.error);

        const d = res.data;

        // Format tanggal
        const lastDate = new Date(d.lastReportedAt);
        const formattedDate = `${String(lastDate.getDate()).padStart(2, '0')}-${String(lastDate.getMonth() + 1).padStart(2, '0')}-${lastDate.getFullYear()}`;

        // Ambil max 3 kategori dari reports
        const recent = (d.reports || []).slice(0, 3);
        const categorySet = new Set();
        recent.forEach(r => r.categories.forEach(id => categorySet.add(id)));
        const categories = Array.from(categorySet).map(id => categoryMap[id] || `Unknown (${id})`);

        // Render hasil
        container.innerHTML += `
<p>IP: ${ip}</p>
  <p>Type: ${d.isPublic ? "Public IP" : "Private IP"}</p>
  <p>Confidence of Abuse: ${d.abuseConfidenceScore}%</p>
  <p>Reports Count: ${d.totalReports} Times</p>
  <p>Last Report: ${formattedDate}</p>
  <p>Category: ${categories.join(', ') || '-'}</p>
  ${d.isWhitelisted ? `<p>Note: Whitelisted</p>` : ""}
  <p><a href="https://www.abuseipdb.com/check/${d.ipAddress}" target="_blank">View on AbuseIPDB</a></p>
        `.trim();

    } catch (err) {
        container.innerHTML += `<p><strong>AbuseIPDB:</strong> Lookup failed (${err.message})</p>`;
    }
}
