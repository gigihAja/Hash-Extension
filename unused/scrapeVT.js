// const puppeteer = require('puppeteer');

// async function scrapeVirusTotal(hash) {
//     const url = `https://www.virustotal.com/gui/file/${hash}/detection`;
//     const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
//     const page = await browser.newPage();

//     await page.goto(url, { waitUntil: 'networkidle2' });

//     // Wait for detection data to load
//     await page.waitForSelector('vt-ui-detections-widget');

//     const result = await page.evaluate(() => {
//         const detectionRatio = document.querySelector('vt-ui-detections-widget .positives')?.textContent?.trim() || null;
//         const communityScore = document.querySelector('vt-ui-score-bar')?.shadowRoot?.querySelector('.score')?.textContent?.trim() || null;

//         const rows = document.querySelectorAll('vt-ui-detections-widget vt-ui-expandable-detection');

//         const maliciousVendors = [];
//         rows.forEach(row => {
//             const verdict = row.querySelector('.verdict')?.textContent?.trim().toLowerCase();
//             if (verdict && verdict !== 'undetected' && !verdict.includes('unable')) {
//                 const vendor = row.querySelector('.engine-name')?.textContent?.trim();
//                 maliciousVendors.push({ vendor, label: verdict });
//             }
//         });

//         return {
//             detectionRatio,
//             communityScore,
//             maliciousVendors
//         };
//     });

//     await browser.close();
//     return result;
// }

// // CLI Entry
// if (require.main === module) {
//     const hash = process.argv[2];
//     if (!hash || hash.length !== 64) {
//         console.error('❌ Provide a valid SHA-256 hash as argument.');
//         process.exit(1);
//     }

//     scrapeVirusTotal(hash).then(result => {
//         console.log(JSON.stringify(result, null, 2));
//     }).catch(err => {
//         console.error('❌ Error during scrape:', err);
//     });
// }
