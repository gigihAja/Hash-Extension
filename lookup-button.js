import { isValidIP, resetContainers, state, createResultCard, parseMultipleInput } from "./popup.js";
import { lookupVirusTotalIP_V3, lookupVirusTotal } from "./virustotal.js";
import { lookupHybridAnalysis } from "./hybrid-analysis.js";
import { lookupOTX } from "./alienvault.js";
import { lookupAbuseIPDB } from "./abuseipdb.js";

export function setupLookupButton() {
    const lookupBtn = document.getElementById("lookupBtn");
    const inputField = document.getElementById("hashInput");

    inputField.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            lookupBtn.click();
        }
    });

    lookupBtn.addEventListener("click", async () => {
        const input = document.getElementById("hashInput").value.trim();
        if (!input) return;

        resetContainers();

        const ipList = input.split(",").map(ip => ip.trim()).filter(ip =>
            /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(ip)
        );
        const isIP = ipList.length > 0;


        if (isIP) {
            state.lastInputType = "ip";

            const vt = document.getElementById("vtResult");
            const ab = document.getElementById("abuseResult");

            vt.style.display = "block";
            ab.style.display = "block";

            vt.querySelector(".content").innerHTML = "";

            ab.querySelector(".content").innerHTML = "";


            for (const ip of ipList) {
                const vtContent = vt.querySelector(".content");
                const abContent = ab.querySelector(".content");

                const vtCard = createResultCard();
                const abCard = createResultCard();

                vtContent.appendChild(vtCard);
                abContent.appendChild(abCard);

                const vtInner = vtCard.querySelector(".content");
                const abInner = abCard.querySelector(".content");

                vtCard.querySelector(".loading").hidden = false;
                abCard.querySelector(".loading").hidden = false;

                await lookupVirusTotalIP_V3(ip, vtInner);
                await lookupAbuseIPDB(ip, abInner);

                vtCard.querySelector(".loading").hidden = true;
                abCard.querySelector(".loading").hidden = true;
            }


            vt.querySelector(".loading").hidden = true;
            ab.querySelector(".loading").hidden = true;

        } else {
            state.lastInputType = "hash";

            const vt = document.getElementById("vtResult");
            const otx = document.getElementById("alienResult");
            const ha = document.getElementById("haResult");

            vt.style.display = "block";
            otx.style.display = "block";
            ha.style.display = "block";

            vt.querySelector(".content").innerHTML = "";
            otx.querySelector(".content").innerHTML = "";
            ha.querySelector(".content").innerHTML = "";

            vt.querySelector(".loading").hidden = false;
            otx.querySelector(".loading").hidden = false;
            ha.querySelector(".loading").hidden = false;

            await lookupVirusTotal(input);
            await lookupOTX(input);
            await lookupHybridAnalysis(input);

            vt.querySelector(".loading").hidden = true;
            otx.querySelector(".loading").hidden = true;
            ha.querySelector(".loading").hidden = true;
        }
    });
}