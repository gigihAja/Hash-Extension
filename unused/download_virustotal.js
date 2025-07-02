// // download_vt_report.js
// const https = require("https");
// const fs = require("fs");
// const path = require("path");

// const hash = process.argv[2]; // Accept hash from command line
// if (!hash) {
//     console.error("❌ Please provide a SHA-256 hash.");
//     process.exit(1);
// }

// const outputFolder = "D:/Gigih/Projects/JavaScript Projects/Hash Extension/Hash Enriched";
// const url = `https://www.virustotal.com/gui/file/${hash}/detection`;

// const outputPath = path.join(outputFolder, `${hash}.html`);

// console.log("⏬ Downloading VT report...");
// https.get(url, (res) => {
//     if (res.statusCode !== 200) {
//         console.error(`❌ Failed to download: Status Code ${res.statusCode}`);
//         return;
//     }

//     const fileStream = fs.createWriteStream(outputPath);
//     res.pipe(fileStream);

//     fileStream.on("finish", () => {
//         fileStream.close();
//         console.log(`✅ Saved to ${outputPath}`);
//     });
// }).on("error", (err) => {
//     console.error(`❌ Error: ${err.message}`);
// });

