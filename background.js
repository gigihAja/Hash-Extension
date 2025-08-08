import CryptoJS from "./crypto-wrapper.js";
// const corsProxy = "https://thingproxy.freeboard.io/fetch/";
const corsProxy = "https://corsproxy.io/?";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    // ✅ FETCH Hybrid Analysis
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
                        'User-Agent': 'Falcon Sandbox'
                    }
                });

                const data = await res.json();
                if (!data || !data.reports || (Array.isArray(data.reports) && data.reports.length === 0)) {
                    console.warn("[HA] ⚠️ No reports found for this hash.");
                    sendResponse({ error: "No results found for the hash." });
                    return;
                }

                const reportArray = Array.isArray(data.reports)
                    ? data.reports
                    : (typeof data.reports === "object" && data.reports !== null)
                        ? Object.entries(data.reports)
                            .filter(([key, value]) => !isNaN(key) && typeof value === 'object')
                            .map(([_, value]) => value)
                        : [];

                function selectTop4Reports(reports) {
                    const successReports = reports.filter(r => r.state === "SUCCESS");
                    const errorReports = reports.filter(r => r.state === "ERROR");

                    const sortedSuccess = [
                        ...successReports.filter(r => r.verdict === "malicious"),
                        ...successReports.filter(r => r.verdict !== "malicious")
                    ];

                    const sortedError = [
                        ...errorReports.filter(r => r.verdict === "malicious"),
                        ...errorReports.filter(r => r.verdict !== "malicious")
                    ];

                    const selected = [];
                    const pool = [...sortedSuccess];

                    const pickOne = (osName) => {
                        const index = pool.findIndex(r =>
                            r.environment_description?.toLowerCase().includes(osName.toLowerCase())
                        );
                        if (index !== -1) {
                            selected.push(pool[index]);
                            pool.splice(index, 1);
                        }
                    };

                    pickOne("Windows 7");
                    pickOne("Windows 10");
                    pickOne("Windows 11");

                    if (pool.length > 0 && selected.length < 4) {
                        selected.push(pool[0]);
                    }

                    const errorPool = [...sortedError];
                    while (selected.length < 4 && errorPool.length > 0) {
                        const next = errorPool.shift();
                        if (!selected.find(r => r.id === next.id)) {
                            selected.push(next);
                        }
                    }

                    return selected;
                }

                const selectedReports = selectTop4Reports(reportArray);
                console.log(`[HA] 📊 Selected top ${selectedReports.length} reports for enrichment`);

                const summaries = [];

                for (const r of selectedReports) {
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
                        console.log("[Hybrid Analysis Raw Response]", rawText);
                        if (!contentType.includes("application/json")) {
                            console.error("❌ Response is not JSON! Dumping raw text:");
                            console.log(rawText.slice(0, 1000));
                            sendResponse({ error: `Response not JSON: ${rawText.slice(0, 300)}` });
                            return;
                        }

                        let summary;
                        try {
                            summary = JSON.parse(rawText);
                            if (typeof summary === 'string') {
                                summary = JSON.parse(summary);
                            }

                            if (summary.message?.includes("archive/container") && Array.isArray(summary.related_id)) {
                                console.log(`📦 ID ${reportId} is archive. Fetching related IDs...`, summary.related_id);

                                for (const relatedId of summary.related_id) {
                                    try {
                                        const relatedRes = await fetch(`${corsProxy}https://www.hybrid-analysis.com/api/v2/report/${relatedId}/summary`, {
                                            headers: {
                                                'api-key': decrypted,
                                                'User-Agent': 'Falcon Sandbox',
                                            }
                                        });

                                        const contentType = relatedRes.headers.get("content-type") || "";
                                        const rawRelatedText = await relatedRes.text();

                                        if (!contentType.includes("application/json")) {
                                            console.warn(`❌ Related ID ${relatedId} returned non-JSON`);
                                            continue;
                                        }

                                        let relatedSummary = JSON.parse(rawRelatedText);
                                        if (typeof relatedSummary === "string") {
                                            relatedSummary = JSON.parse(relatedSummary);
                                        }

                                        summaries.push(relatedSummary);
                                        console.log(`✅ Related summary added for ID: ${relatedId}`);
                                    } catch (e) {
                                        console.warn(`⚠️ Failed to fetch related summary ${relatedId}:`, e.message);
                                        continue;
                                    }
                                }
                            } else {
                                if (
                                    summary &&
                                    summary.state !== "ERROR" &&
                                    summary.verdict &&
                                    Array.isArray(summary.signatures) &&
                                    summary.signatures.length > 0
                                ) {
                                    summaries.push(summary);
                                } else {
                                    console.log(`[HA] ⛔ Skipping invalid/empty summary for report ID: ${reportId}`);
                                }
                            }

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

            } catch (e) {
                console.error("❌ Fatal error in fetchHA:", e.message);
                sendResponse({ error: "Fatal error: " + e.message });
            }
        })();

        return true;
    }

    // ✅ FETCH AbuseIPDB
    else if (request.action === 'fetchAbuseIPDB') {
        (async () => {
            try {
                const ip = request.ip;
                const url = `${corsProxy}https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&verbose`;

                const res = await fetch(url, {
                    headers: {
                        "Key": request.apiKey,
                        "Accept": "application/json"
                    }
                });

                // const rawText = await res.text();
                // console.log("[AbuseIPDB Raw Response]", rawText);

                const data = await res.json();
                if (!data || !data.data) {
                    sendResponse({ error: "Invalid response from AbuseIPDB" });
                    return;
                }

                sendResponse({ data: data.data });
            } catch (err) {
                sendResponse({ error: err.message });
            }
        })();

        return true;
    }

});