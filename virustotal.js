const vtKey = "c01ba790c0bdde3781b873ab29d6f349a87312e3729e2da0f56690c1c67a07e5";


import { verdictColor } from "./popup.js";

export async function lookupVirusTotal(hash, container, key = vtKey) {


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
            const attrs = data.data.attributes;
            const stats = attrs.last_analysis_stats;
            const results = attrs.last_analysis_results;

            // ✅ Ambil file name dengan fallback berurutan
            const fileName =
                attrs.meaningful_name ||
                attrs["original name"] ||
                (attrs.names?.find(name => !name.includes("%"))) ||
                "Unknown";

            const isMalicious = stats.malicious > 0;
            const detectionColor = isMalicious ? "#ed1b24" : "#4ade80";

            const malicious = Object.entries(results)
                .filter(([_, result]) => result.category === "malicious")
                .map(([vendor, result]) => {
                    return `<li><strong>${vendor}:</strong> <span style="color:${detectionColor}">${result.result}</span></li>`;
                });

            content.innerHTML = `
<p><strong>File Name:</strong> ${fileName}</p>
<p><strong>Detections:</strong> ${stats.malicious} / ${Object.keys(results).length}</p>
${malicious.length > 0 ? `<p><strong>Malicious Vendors:</strong></p><ul>${malicious.join("")}</ul>` : ""}
<p><a href="https://www.virustotal.com/gui/file/${hash}" target="_blank">View on VirusTotal</a></p>
`.trim();
        } else {
            content.innerHTML = "<p>No report found for this hash.</p>";
        }
    } catch (err) {
        content.innerHTML = `<p>Error: ${err.message}</p>`;
    } finally {
        vt.querySelector(".loading").hidden = true;
    }
}


export async function lookupVirusTotalIP_V3(ip, container) {
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
<div style="margin-bottom: 1.5rem; padding-bottom: 1rem;">
<p><strong>IP:</strong> ${ip}</p>
<p><strong>Country:</strong> ${country}</p>
<p><strong>ASN:</strong> ${asn}</p>

<p><strong style="${analysisStyle}">Analysis:</strong> <span style="${analysisStyle}">${lastAnalysisStats.malicious ?? 0} malicious</span> / ${Object.keys(lastAnalysisResults).length} total</p>
${vendors.length > 0 ? `
<p><strong>Detected By:</strong></p>
<ul>
${vendors.map(([vendor, res]) => {
            const color = verdictColor(res.category);
            return `<li><strong>${vendor}:</strong> ${res.result} <span style="color:${color}">[${res.category}]</span></li>`;
        }).join("\n")}
</ul>` : ""}

<p><a href="https://www.virustotal.com/gui/ip-address/${ip}/detection" target="_blank">View on VirusTotal</a></p>
</div>
`.trim();
    } catch (err) {
        container.innerHTML += `<p><strong>${ip}</strong> — Error: ${err.message}</p>`;
    }
}
