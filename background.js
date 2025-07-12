import CryptoJS from "./crypto-wrapper.js";
const corsProxy = "https://thingproxy.freeboard.io/fetch/";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fetchHA') {
        (async () => {
            try {
                const hash = request.hash;
                console.log(`[HA] 🔍 Fetching report IDs for hash: ${hash}`);

                const decrypted = CryptoJS.AES.decrypt(request.passphrase, 'secret').toString(CryptoJS.enc.Utf8);
                if (!decrypted) {
                    sendResponse({ error: "API key decryption failed" });
                    return;
                }

                const searchUrl = `${corsProxy}https://www.hybrid-analysis.com/api/v2/search/hash?hash=${hash}`;
                const res = await fetch(searchUrl, {
                    headers: {
                        'api-key': decrypted,
                        'User-Agent': 'Falcon Sandbox',
                    }
                });

                const data = await res.json();

                if (!data.reports || data.reports.length === 0) {
                    sendResponse({ error: "No reports found for this hash" });
                    return;
                }

                const reportArray = Array.isArray(data.reports)
                    ? data.reports
                    : Object.entries(data.reports)
                        .filter(([key, value]) => !isNaN(key) && typeof value === 'object')
                        .map(([_, value]) => value);

                console.log(`[HA] ✅ Found ${reportArray.length} report(s) from hash`);

                const summaries = [];

                for (const r of reportArray) {
                    const reportId = r.id || r.job_id || r.report_id || r.submission_id;
                    if (!reportId) {
                        console.warn(`[HA] ❌ Missing report ID in entry:`, r);
                        continue;
                    }

                    console.log(`[HA] 📄 Fetching summary for report ID: ${reportId}`);
                    try {
                        const summaryRes = await fetch(`${corsProxy}https://www.hybrid-analysis.com/api/v2/report/${reportId}/summary`, {
                            headers: {
                                'api-key': decrypted,
                                'User-Agent': 'Falcon Sandbox',
                            }
                        });

                        const contentType = summaryRes.headers.get("content-type") || "";
                        const rawText = await summaryRes.text();
                        console.log("📦 Content-Type:", contentType);
                        console.log("📦 rawText Preview:", rawText.slice(0, 500));

                        if (!contentType.includes("application/json")) {
                            console.error("❌ Response is not JSON! Dumping raw text:");
                            console.log(rawText.slice(0, 1000)); // batasi 1000 karakter
                            sendResponse({ error: `Response not JSON: ${rawText.slice(0, 300)}` });
                            return;
                        }

                        let summary;
                        try {
                            summary = JSON.parse(rawText);
                            if (typeof summary === 'string') {
                                summary = JSON.parse(summary); // Fallback double-parse
                            }
                            summaries.push(summary);
                        } catch (e) {
                            console.error("⚠️ Failed to parse summary:", e.message);
                            console.log("🧪 rawText preview:\n", rawText.slice(0, 500));
                            continue;
                        }

                    } catch (e) {
                        console.warn(`[HA] ⚠️ Error fetching/parsing summary ${reportId}:`, e.message);
                        continue;
                    }
                }

                console.log(`[HA] ✅ Sent ${summaries.length} summaries to popup`);
                sendResponse({ summaries });

            } catch (err) {
                console.error(`[HA] ❌ Unexpected error in fetchHA:`, err.message);
                sendResponse({ error: err.message });
            }
        })();

        return true;
    }
});
