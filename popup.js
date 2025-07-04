const vtKey = "c01ba790c0bdde3781b873ab29d6f349a87312e3729e2da0f56690c1c67a07e5";
const otxKey = "c01ba790c0bdde3781b873ab29d6f349a87312e3729e2da0f56690c1c67a07e5";
const ENCRYPTED_API_KEY = "U2FsdGVkX190tktSa1oAhdRmRMP1+Ly9Dyfzg8xkkjQzCeIZeBFv9fBmIDnHhCtkjd8cBGrneCS793dxn/NEqYuqjPPHxe1zdqSrWuxV1q5jCRrjdBO5coCnjf4ChpJa=";

let lastInputType = "unknown"; // IP or Hash

document.getElementById("lookupBtn").addEventListener("click", async () => {
    const input = document.getElementById("hashInput").value.trim();
    if (!input) return alert("Enter a SHA-256 hash or IP address");

    // CLEAR ALL RESULTS FIRST
    const vt = document.getElementById("vtResult");
    const otx = document.getElementById("otxResult");
    const ha = document.getElementById("haResult");

    vt.querySelector(".loading").hidden = false;
    vt.querySelector(".content").innerHTML = "";

    otx.querySelector(".loading").hidden = true;
    otx.querySelector(".content").innerHTML = "";

    ha.querySelector(".loading").hidden = true;
    ha.querySelector(".content").innerHTML = "";

    // DETECT MULTIPLE IPs
    const ipList = input.split(",").map(ip => ip.trim()).filter(ip =>
        /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(ip)
    );

    if (ipList.length > 0) {
        lastInputType = "ip";
        document.getElementById("copyAllContainer").hidden = false;
        for (const ip of ipList) {
            await lookupVirusTotalIP_V3(ip, vt.querySelector(".content"));
        }
        vt.querySelector(".loading").hidden = true;
        return; // skip OTX + HA
    }
    lastInputType = "hash"

    // If SHA256 hash → continue to all lookups
    document.getElementById("copyAllContainer").hidden = false;

    await lookupVirusTotal(input);
    await lookupOTX(input);
    await lookupHybridAnalysis(input);

    vt.querySelector(".loading").hidden = true;
});


function verdictColor(label) {
    if (!label) return "gray";
    return label.toLowerCase().includes("suspicious") ? "orange" : "red";
}


async function lookupVirusTotalIP_V3(ip, container) {
    try {
        const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: {
                "x-apikey": vtKey
            }
        });

        if (!res.ok) throw new Error(`VT API error: ${res.status}`);
        const data = await res.json();
        const attr = data.data.attributes;

        const country = attr.country || "N/A";
        const asn = attr.asn || "N/A";
        const lastAnalysisStats = attr.last_analysis_stats || {};
        const lastAnalysisResults = attr.last_analysis_results || {};

        const vendors = Object.entries(lastAnalysisResults).filter(([_, result]) =>
            result.category === "malicious" || result.category === "suspicious"
        );

        const analysisStyle = (lastAnalysisStats.malicious ?? 0) > 0
            ? 'color: #f87171; font-weight: bold;'
            : 'color: #4ade80;';

        container.innerHTML += `
<div style="margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px dashed #ccc">
  <p><strong>IP:</strong> ${ip}</p>
  <p><strong>Country:</strong> ${country}</p>
  <p><strong>ASN:</strong> ${asn}</p>

  <p><strong style="${analysisStyle}">Analysis:</strong> <span style="${analysisStyle}">${lastAnalysisStats.malicious ?? 0} malicious</span> / ${Object.keys(lastAnalysisResults).length} total</p>

  <p><strong>Detected By:</strong></p>
  <ul>
    ${vendors.map(([vendor, res]) => {
            const color = verdictColor(res.category);
            return `<li><strong>${vendor}:</strong> ${res.result} <span style="color:${color}">[${res.category}]</span></li>`;
        }).join("")}
  </ul>
  <p><a href="https://www.virustotal.com/gui/ip-address/${ip}/detection" target="_blank">View on VirusTotal</a></p>
</div>
`;
    } catch (err) {
        container.innerHTML += `<p><strong>${ip}</strong> — Error: ${err.message}</p>`;
    }
}

/*
//VIRUSTOTAL V2 (WITHOUT FILE-NAME)
//WARNING!! **DO NOT DELETE, FOR SAFETY FALLBACK**

async function lookupVirusTotal(hash) {
    const vt = document.getElementById("vtResult");
    vt.querySelector(".loading").hidden = false;
    const content = vt.querySelector(".content");
    content.innerHTML = "";

    try {
        const res = await fetch(
            `https://www.virustotal.com/vtapi/v2/file/report?apikey=${vtKey}&resource=${hash}`
        );
        const data = await res.json();

        if (data.response_code === 1) {
            const isMalicious = data.positives > 0;
            const detectionColor = isMalicious ? "#ed1b24" : "#4ade80";

            const malicious = Object.entries(data.scans)
                .filter(([_, result]) => result.detected)
                .map(([vendor, result]) => {
                    return `<li><strong>${vendor}:</strong> <span style="color:${detectionColor}">${result.result}</span></li>`;
                });

            content.innerHTML = `
                <p><strong style="color: ${detectionColor}; font-size: 14px;">Detections:</strong> 
                <span style="color: ${detectionColor}; font-weight: bold;">${data.positives} / ${data.total}</span></p>

                <p><strong style="font-size: 14px;">Malicious Vendors:</strong></p>
                <ul style="margin-top: 0.5rem; padding-left: 1.2rem;">${malicious.join("")}</ul>

                <p style="margin-top: 1rem;"><a href="${data.permalink}" target="_blank" style="color:#93c5fd; text-decoration: underline;">View on VirusTotal</a></p>
            `;
        } else {
            content.innerHTML = "<p>No report found for this hash.</p>";
        }
    } catch (err) {
        content.innerHTML = `<p>Error: ${err.message}</p>`;
    } finally {
        vt.querySelector(".loading").hidden = true;
    }
}
*/

async function lookupVirusTotal(hash) {
    const vt = document.getElementById("vtResult");
    vt.querySelector(".loading").hidden = false;
    const content = vt.querySelector(".content");
    content.innerHTML = "";

    try {
        const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: {
                "accept": "application/json",
                "x-apikey": vtKey
            }
        });

        const data = await res.json();

        if (data.data && data.data.attributes) {
            const stats = data.data.attributes.last_analysis_stats;
            const results = data.data.attributes.last_analysis_results;
            const fileName = data.data.attributes.names?.[0] || "Unknown";


            const isMalicious = stats.malicious > 0;
            const detectionColor = isMalicious ? "#ed1b24" : "#4ade80";

            const malicious = Object.entries(results)
                .filter(([_, result]) => result.category === "malicious")
                .map(([vendor, result]) => {
                    return `<li><strong>${vendor}:</strong> <span style="color:${detectionColor}">${result.result}</span></li>`;
                });

            content.innerHTML = `
                <p><strong>File Name:</strong> ${fileName}</p>

                <p><strong style="color: ${detectionColor}; font-size: 14px;">Detections:</strong> 
                <span style="color: ${detectionColor}; font-weight: bold;">${stats.malicious} / ${Object.keys(results).length}</span></p>

                <p><strong style="font-size: 14px;">Malicious Vendors:</strong></p>
                <ul style="margin-top: 0.5rem; padding-left: 1.2rem;">${malicious.join("")}</ul>

                <p style="margin-top: 1rem;"><a href="https://www.virustotal.com/gui/file/${hash}" target="_blank" style="color:#93c5fd; text-decoration: underline;">View on VirusTotal</a></p>
            `;
        } else {
            content.innerHTML = "<p>No report found for this hash.</p>";
        }
    } catch (err) {
        content.innerHTML = `<p>Error: ${err.message}</p>`;
    } finally {
        vt.querySelector(".loading").hidden = true;
    }
}



async function lookupOTX(hash) {
    const otx = document.getElementById("otxResult");
    otx.querySelector(".loading").hidden = false;
    const content = otx.querySelector(".content");
    content.innerHTML = "";

    try {
        const [generalRes, analysisRes] = await Promise.all([
            fetch(`https://otx.alienvault.com/api/v1/indicators/file/${hash}/general`, {
                headers: { "X-OTX-API-KEY": otxKey }
            }),
            fetch(`https://otx.alienvault.com/api/v1/indicators/file/${hash}/analysis`, {
                headers: { "X-OTX-API-KEY": otxKey }
            })
        ]);

        const general = await generalRes.json();
        const analysis = await analysisRes.json();

        const plugins = analysis.analysis?.plugins || {};
        const cuckooResult = plugins?.cuckoo?.result || {};
        const signatures = cuckooResult?.signatures || [];

        // Score: use combined_score or fallback to score or "Not available"
        const score = cuckooResult.info?.combined_score ??
            cuckooResult.info?.score ??
            "Not available";

        // AV Detection: only include plugins with detection string (avoid object object)
        const avDetections = Object.entries(plugins)
            .filter(([name, p]) =>
                name !== "yarad" &&
                p.results &&
                typeof p.results.detection === "string"
            )
            .map(([name, p]) => `${name}: ${p.results.detection}`);

        // YARA Detection
        const yaraResults = plugins?.yarad?.results?.detection ?? [];
        const yaraDetections = yaraResults.map(r => `${r.rule_name} (Severity: ${r.severity})`);

        // Alerts
        const alerts = signatures.map(sig => sig.name).filter(Boolean);

        // Pulses
        const pulses = general.pulse_info?.count ?? 0;

        content.innerHTML = `
            <p><strong>Score:</strong> ${score}</p>
            <p><strong>Pulses:</strong> ${pulses}</p>

            <p><strong>AV Detections (${avDetections.length}):</strong></p>
            <ul>
            ${avDetections.map(d => `<li style="color:#ed1b24">${d}</li>`).join("")}
            </ul>


            <p><strong>YARA Detections (${yaraDetections.length}):</strong></p>
            <ul>${yaraDetections.map(y => `<li>${y}</li>`).join("")}</ul>

            <p><strong>Alerts (${alerts.length}):</strong></p>
            <ul>${alerts.map(a => `<li>${a}</li>`).join("")}</ul>

            <p><a href="https://otx.alienvault.com/indicator/file/${hash}" target="_blank">View on OTX</a></p>
        `;
        /*
                //put this inside of innerHTML for Raw JSON Analysis
        <hr style="margin:1rem 0">
                    <p><strong>Raw JSON (analysis):</strong></p>
                    <pre style="white-space: pre-wrap; font-size: 12px; background: #f7f7f7; padding: 10px; border-radius: 6px; max-height: 300px; overflow-y: auto;">
        ${JSON.stringify(analysis, null, 2)}
                    </pre>
                */

    } catch (err) {
        content.innerHTML = `<p>Error: ${err.message}</p>`;
    } finally {
        otx.querySelector(".loading").hidden = true;
    }
}


// Add this function to call background.js
async function lookupHybridAnalysis(hash) {
    const section = document.querySelector("#haResult");
    const loadingDiv = section.querySelector(".loading");
    const contentDiv = section.querySelector(".content");

    loadingDiv.hidden = false;
    contentDiv.innerHTML = "";


    console.log("[popup] Sending message to background...");
    chrome.runtime.sendMessage({ action: "fetchHA", hash, passphrase: ENCRYPTED_API_KEY }, (res) => {
        console.log("✅ HA response:", res);
        loadingDiv.hidden = true;

        if (res.error) {
            contentDiv.innerHTML = `<p>${res.error}</p>`;
            return;
        }

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

        enriched.sort((a, b) => new Date(b.analysis_start_time) - new Date(a.analysis_start_time));

        contentDiv.innerHTML = enriched.map((entry) => {
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

            return `
                <div class="ha-report">
                    <div class="ha-header">
                        <div class="ha-title">${scoreIcon}${entry.submit_name}</div>
                        <div class="badge ${badgeClass}">${entry.verdict}</div>
                    </div>
                    <div class="ha-meta">
                        <div><strong>Environment:</strong> ${entry.environment}</div>
                        <div><strong>Analysis Time:</strong> ${entry.analysis_start_time}</div>
                        <div><strong>Threat Score:</strong> ${entry.threat_score}</div>
                        <div><strong>AV Detection:</strong> ${entry.av_detect}%</div>
                    </div>
                    <div class="ha-section">
                        <strong>File:</strong> ${entry.type}, ${entry.size} bytes
                    </div>
                    <div class="ha-section">
                        <strong>MITRE ATT&CK:</strong> <span title="${tags}">${tags.slice(0, 80)}${tags.length > 80 ? "..." : ""}</span>
                    </div>
                    <div class="ha-section">
                        <strong>Processes:</strong> ${entry.processes.length} | 
                        <strong>Extracted Files:</strong> ${entry.extracted_files.length} | 
                        <strong>Network Connections:</strong> ${entry.net_conn}
                    </div>
                <p style="margin-top: 1rem;"><a href="https://hybrid-analysis.com/search?query=${hash}" target="_blank" style="color:#93c5fd; text-decoration: underline;">View on Hybrid Analysis</a></p>
                    </div>
            `;
        }).join("");
    });
}


document.getElementById("copyAllBtn").addEventListener("click", () => {
    const cleanText = (containerId) => {
        const container = document.querySelector(`#${containerId} .content`);
        if (!container) return "";
        const clone = container.cloneNode(true);

        clone.querySelectorAll("a").forEach(a => a.remove());

        clone.querySelectorAll("ul").forEach(ul => {
            const items = Array.from(ul.querySelectorAll("li"))
                .map(li => `- ${li.innerText.trim()}`);
            const replacement = document.createElement("div");
            replacement.innerText = items.join("\n");
            ul.replaceWith(replacement);
        });

        return clone.innerText.trim();
    };

    const sections = [];
    const vt = cleanText("vtResult");
    const otx = cleanText("otxResult");
    const ha = cleanText("haResult");
    
    let combined = "";
    
    if(lastInputType === "ip")
    {
        if(!vt.trim())
            return alert("No IP result to copy :(");
        combined = `#IP :\nVirusTotal:\n${vt}`;
    }
    else if(lastInputType === "hash")
    {
        const sections = [];
        if (vt) sections.push("VirusTotal:\n" + vt);
        if (otx) sections.push("AlienVault OTX:\n" + otx);
        if (ha) sections.push("Hybrid Analysis:\n" + ha);
        combined = "#Hash :\n" + sections.join();
        if(!sections.length) return alert("No hash result to copy :(");
    }
    else
        return alert("No result to copy...");

    console.log(combined);

    navigator.clipboard.writeText(combined)
        .then(() => showCopyToast("✔ All results copied!"))
        .catch(err => alert("Failed to copy: " + err));
});


function showCopyToast(msg) {
    const toast = document.createElement("div");
    toast.innerText = msg;
    toast.style.position = "fixed";
    toast.style.bottom = "20px";
    toast.style.right = "20px";
    toast.style.background = "#22c55e";
    toast.style.color = "#fff";
    toast.style.padding = "10px 16px";
    toast.style.borderRadius = "8px";
    toast.style.boxShadow = "0 2px 6px rgba(0,0,0,0.3)";
    toast.style.fontSize = "14px";
    toast.style.zIndex = 9999;
    toast.style.transition = "opacity 0.3s ease";

    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 500);
    }, 2000);
}