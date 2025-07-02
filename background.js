// // chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
// //     if (request.action === "fetchVT") {
// //         const vtUrl = `https://www.virustotal.com/gui/file/${request.hash}/detection`;

// //         fetch(vtUrl)
// //             .then(res => res.text())
// //             .then(html => {
// //                 const parser = new DOMParser();
// //                 const doc = parser.parseFromString(html, "text/html");

// //                 // Sayangnya, VirusTotal pakai JS frontend (React), jadi isi <body> kosong
// //                 // Solusi: Gunakan endpoint `/gui/file/<hash>/detection` → tidak bisa fetch langsung karena CORS
// //                 // Jadi, alternatif: gunakan public API atau headless browser (Puppeteer) → tidak bisa dari extension

// //                 sendResponse({ success: false, error: "HTML kosong. Tidak bisa di-parse tanpa API." });
// //             })
// //             .catch(error => {
// //                 console.error("Fetch error:", error);
// //                 sendResponse({ success: false });
// //             });

// //         return true; // Needed for async sendResponse
// //     }
// // });



// //



// const haKey = "vzuy4foqd2220d1enqpifi02c6fbce26pngma1p62d294bc85rpy6t0l446473b1";

// chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
//     if (request.type === "lookupHybridAnalysis") {
//         fetch(`https://www.hybrid-analysis.com/api/v2/search/hash?hash=${request.hash}`, {
//             headers: {
//                 "api-key": haKey,
//                 "User-Agent": "Falcon Sandbox"
//             }
//         })
//             .then(res => res.json())
//             .then(data => sendResponse(data))
//             .catch(err => sendResponse({ error: err.message }));
//         return true;
//     }

//     if (request.type === "lookupHybridSummary") {
//         fetch(`https://www.hybrid-analysis.com/api/v2/report/${request.reportId}/summary`, {
//             headers: {
//                 "api-key": haKey,
//                 "User-Agent": "Falcon Sandbox"
//             }
//         })
//             .then(res => res.json())
//             .then(data => sendResponse(data))
//             .catch(err => sendResponse({ error: err.message }));
//         return true;
//     }
// });


// // const haKey = "vzuy4foqd2220d1enqpifi02c6fbce26pngma1p62d294bc85rpy6t0l446473b1";

// // chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
// //   if (message.type === "lookupHA") {
// //     const hash = message.hash;

// //     fetch(`https://www.hybrid-analysis.com/api/v2/search/hash?hash=${hash}`, {
// //       headers: {
// //         "api-key": haKey,
// //         "User-Agent": "Falcon Sandbox"
// //       }
// //     })
// //       .then(res => res.json())
// //       .then(data => sendResponse({ success: true, data }))
// //       .catch(err => sendResponse({ success: false, error: err.message }));

// //     return true; // <== keep the message channel open
// //   }
// // });

//
//

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "fetchHA") {
        const hash = request.hash;
        fetch(`https://www.hybrid-analysis.com/api/v2/search/hash?hash=${hash}`, {
            headers: {
                "api-key": "vzuy4foqd2220d1enqpifi02c6fbce26pngma1p62d294bc85rpy6t0l446473b1", // ganti dengan yang benar
                "User-Agent": "Falcon Sandbox"
            }
        })
            .then(res => res.json())
            .then(async data => {
                if (!data.reports || !Array.isArray(data.reports)) {
                    sendResponse({ summaries: [] });
                    return;
                }

                const summaries = await Promise.all(
                    data.reports.map(async report => {
                        try {
                            const res = await fetch(`https://www.hybrid-analysis.com/api/v2/report/${report.id}/summary`, {
                                headers: {
                                    "api-key": "vzuy4foqd2220d1enqpifi02c6fbce26pngma1p62d294bc85rpy6t0l446473b1", // ganti juga ini
                                    "User-Agent": "Falcon Sandbox"
                                }
                            });
                            return await res.json();
                        } catch (e) {
                            return null;
                        }
                    })
                );

                sendResponse({ summaries: summaries.filter(Boolean) });
            })
            .catch(err => {
                console.error("Hybrid Analysis fetch error:", err);
                sendResponse({ error: err.message });
            });

        // penting! agar response async diterima:
        return true;
    }
});
