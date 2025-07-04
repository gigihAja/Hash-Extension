// import { report } from "process";
import CryptoJS from "./crypto-wrapper.js";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fetchHA') {
        (async () => {
            try {
                console.log('[background] 🔐 Decrypting API key...');
                const decrypted = CryptoJS.AES.decrypt(request.passphrase, 'secret').toString(CryptoJS.enc.Utf8);
                console.log("🔓 Decrypted API Key:", decrypted);
                if (!decrypted) {
                    sendResponse({ error: "API key decryption failed" });
                    return;
                }

                const proxyUrl = 'https://corsproxy.io/?https://www.hybrid-analysis.com/api/v2/search/hash?hash=' + request.hash;

                const res = await fetch(proxyUrl, {
                    headers: {
                        'api-key': decrypted,
                        'User-Agent': 'Falcon Sandbox',
                    }
                });
                //
                //
                //
                const data = await res.json();
                console.log(data);
                console.log("[background] 🔍 Search response data:", data);
                console.log("📥 RAW data.reports:", JSON.stringify(data.reports, null, 2));

                if (!data.reports || Object.keys(data.reports).length === 0) {
                    sendResponse({ error: "No reports found for this hash" });
                    return;
                }

                const reportArray = Object.entries(data.reports)
                    .filter(([key, value]) =>
                        !isNaN(key) && typeof value === 'object' && value !== null
                    )
                    .map(([_, value]) => value);

                const summaries = [];
                for (const r of reportArray) {
                    console.log(reportArray);
                    const reportId = r.id || r.job_id || r.report_id || r.submission_id;
                    if (!reportId) {
                        console.warn("❗ Report item missing ID:", r);
                        continue;
                    }

                    const summaryRes = await fetch(`https://corsproxy.io/?https://www.hybrid-analysis.com/api/v2/report/${reportId}/summary`, {
                        headers: {
                            'api-key': decrypted,
                            'User-Agent': 'Falcon Sandbox',
                        }
                    });

                    if (!summaryRes.ok) {
                        console.warn(`⚠️ Failed to fetch summary for job: ${reportId}`, summaryRes.status);
                        continue;
                    }

                    const summary = await summaryRes.json();
                    summaries.push(summary);
                }




                sendResponse({ summaries });
            } catch (err) {
                console.error("[background] ❌ Error in fetchHA:", err);
                sendResponse({ error: err.message });
            }
        })();

        return true; // ✅ penting agar port tetap terbuka!
    }
});
