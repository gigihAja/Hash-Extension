const otxKey = "c01ba790c0bdde3781b873ab29d6f349a87312e3729e2da0f56690c1c67a07e5";

export async function lookupOTX(hash, container) {
    const otx = container || document.getElementById("alienResult");
    if (!otx) {
        console.error("❌ OTX container not found");
        return;
    }

    // ✅ Tambahkan bagian ini supaya section muncul di DOM saat copy
    otx.style.display = "block";

    const loading = otx.querySelector(".loading");
    const content = otx.querySelector(".content");

    if (loading) loading.hidden = false;
    if (content) content.innerHTML = "";

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

        const score = cuckooResult.info?.combined_score ??
            cuckooResult.info?.score ??
            "Not available";

        const avDetections = Object.entries(plugins)
            .filter(([name, p]) =>
                name !== "yarad" &&
                p.results &&
                typeof p.results.detection === "string"
            )
            .map(([name, p]) => `${name}: ${p.results.detection}`);

        const yaraResults = plugins?.yarad?.results?.detection ?? [];
        const yaraDetections = yaraResults.map(r => `${r.rule_name} (Severity: ${r.severity})`);

        const alerts = signatures.map(sig => sig.name).filter(Boolean);
        const pulses = general.pulse_info?.count ?? 0;

        content.innerHTML = `
<p><strong>Score:</strong> ${score}</p>
<p><strong>Pulses:</strong> ${pulses}</p>
<p><strong>AV Detections (${avDetections.length}):</strong></p>
<ul>${avDetections.map(d => `<li style="color:#ed1b24">${d}</li>`).join("")}</ul>
<p><strong>YARA Detections (${yaraDetections.length}):</strong></p>
<ul>${yaraDetections.map(y => `<li>${y}</li>`).join("")}</ul>
<p><strong>Alerts (${alerts.length}):</strong></p>
<ul>${alerts.map(a => `<li>${a}</li>`).join("")}</ul>
<p><a href="https://otx.alienvault.com/indicator/file/${hash}" target="_blank">View on OTX</a></p>
        `.trim();

        /*
        // Optional: Add Raw JSON
        <hr style="margin:1rem 0">
        <p><strong>Raw JSON (analysis):</strong></p>
        <pre style="white-space: pre-wrap; font-size: 12px; background: #f7f7f7; padding: 10px; border-radius: 6px; max-height: 300px; overflow-y: auto;">
${JSON.stringify(analysis, null, 2)}
        </pre>
        */
    } catch (err) {
        content.innerHTML = `<p>Error: ${err.message}</p>`;
    } finally {
        if (loading) loading.hidden = true;
    }
}
