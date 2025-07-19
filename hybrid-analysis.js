const ENCRYPTED_API_KEY = "U2FsdGVkX190tktSa1oAhdRmRMP1+Ly9Dyfzg8xkkjQzCeIZeBFv9fBmIDnHhCtkjd8cBGrneCS793dxn/NEqYuqjPPHxe1zdqSrWuxV1q5jCRrjdBO5coCnjf4ChpJa=";


import { createResultCard } from "./popup.js";

export async function lookupHybridAnalysis(hash) {
    return new Promise((resolve) => {
        const section = document.querySelector("#haResult");
        const loadingDiv = section.querySelector(".loading");
        const contentDiv = section.querySelector(".content");

        section.style.display = "block";
        loadingDiv.hidden = false;
        contentDiv.innerHTML = "";


        console.log("[popup] Sending message to background...");

        chrome.runtime.sendMessage(
            { action: "fetchHA", hash, passphrase: ENCRYPTED_API_KEY },
            (res) => {
                console.log("✅ [popup] Received response from background:", res);
                loadingDiv.hidden = true;

                if (res.error) {
                    let html = `<p style="color:#f87171;"><strong>${res.error}</strong></p>`;
                    if (res.raw) {
                        html += `
<pre style="white-space: pre-wrap; font-size: 12px; background: #2e2e42; padding: 10px; border-radius: 6px; max-height: 300px; overflow-y: auto; border: 1px solid #444;">
${res.raw.replace(/</g, "&lt;").replace(/>/g, "&gt;")}
</pre>`;
                    }
                    contentDiv.innerHTML = html;
                    return;
                }

                if (!res.summaries || res.summaries.length === 0) {
                    contentDiv.innerHTML = `<p style="color:#f87171;"><strong>No reports found for this hash.</strong></p>`;
                    return;
                }


                console.log("✅ [popup] Summary parsing...");
                const enriched = res.summaries.map((s) => ({
                    id: s.id,
                    environment: s.environment_description || "-",
                    verdict: s.verdict || "-",
                    submit_name: s.submissions?.[0]?.filename || "Unknown file",
                    type: Array.isArray(s.type_short) ? s.type_short.join(", ") : s.type || "-",
                    size: s.size ?? "-",
                    analysis_start_time: s.submissions?.[0]?.created_at || "-",
                    threat_level: s.threat_level ?? "-",
                    threat_score: s.threat_score ?? 0,
                    av_detect: typeof s.av_detect === "number" ? s.av_detect : 0,
                    mitre: s.mitre_attcks || [],
                    extracted_files: s.extracted_files || [],
                    processes: s.processes || [],
                    net_conn: s.total_network_connections ?? 0,
                }));

                console.log("✅ [popup] Sorting by date...");
                enriched.sort((a, b) => new Date(b.analysis_start_time) - new Date(a.analysis_start_time));

                console.log("✅ [popup] Rendering summaries...");

                //Change Analysis Date format to DD-MM-YYYY 
                function formatDate(isoDateStr) {
                    const date = new Date(isoDateStr);
                    const day = String(date.getDate()).padStart(2, '0');
                    const month = String(date.getMonth() + 1).padStart(2, '0');
                    const year = date.getFullYear();
                    return `${day}-${month}-${year}`;
                }


                for (let index = 0; index < enriched.length; index++) {
                    const entry = enriched[index];

                    const badgeClass =
                        entry.verdict === "malicious"
                            ? "badge-red"
                            : entry.verdict === "suspicious"
                                ? "badge-yellow"
                                : "badge-green";

                    const scoreIcon = entry.threat_score > 70 ? "⚠️ " : "";

                    const tags = entry.mitre
                        .map((m) => `${m.tactic} (${m.technique} / ${m.attck_id})`)
                        .join(", ");

                    const maliciousIndicators = (res.summaries[index]?.signatures || []).filter(sig =>
                        (sig.threat_level_human === "suspicious" || sig.threat_level_human === "malicious") &&
                        sig.category !== "General"
                    );


                    const card = createResultCard();
                    const inner = card.querySelector(".content");


                    inner.innerHTML = `
<p><strong>Report ${index + 1}:</strong></p>
<p>File Name: ${entry.submit_name}</p>
<p>State: ${entry.verdict}</p>
<p>Environment: ${entry.environment}</p>
<p>Analysis Time: ${formatDate(entry.analysis_start_time)}</p>
<p>Threat Score: ${entry.threat_score}</p>
<p>AV Detection: ${entry.av_detect}%</p>
<p>File Type: ${entry.type}, ${entry.size} bytes</p>

${maliciousIndicators.length > 0
                            ? `<div style="margin-top:10px;">
<strong>Malicious Indicators:</strong>
<ul style="margin-left:1rem;">
${maliciousIndicators.map(sig => {
                                const textColor = sig.threat_level_human === "malicious" ? "#b91c1c" : "#ea580c"; // red or orange
                                return `
<li>
<span style="color:${textColor}; font-weight:600;">
${sig.category}
</span> : ${sig.name}
</li>`;
                            }).join('')}
</ul>
</div>`
                            :
                            `<p>No suspicious or malicious indicators found in this report.</p>`}

<p style="margin-top: 1rem;">
<a href="https://hybrid-analysis.com/search?query=${hash}" target="_blank" class="external-link" style="color:#93c5fd; text-decoration: underline;">
        View on Hybrid Analysis
    </a>
</p>
`.trim();
                    contentDiv.appendChild(card);
                    card.querySelector(".loading").hidden = true;
                }
                loadingDiv.hidden = true;
                resolve();
                //.join("");
            })
        console.log("✅ [popup] Rendering complete.");
    }
    );
}