import { setupLookupButton } from "./lookup-button.js";
import { setupCopyAllButton } from "./copy-all-button.js";
import { setupOpenAllLinksButton } from "./open-all-links.js";

// Global state object to store input type
export const state = {
    lastInputType: null
};

export function isValidIP(input) {
    const ipRegex = /^(25[0-5]|2[0-4]\d|1\d\d|\d\d?)\.(25[0-5]|2[0-4]\d|1\d\d|\d\d?)\.(25[0-5]|2[0-4]\d|1\d\d|\d\d?)\.(25[0-5]|2[0-4]\d|1\d\d|\d\d?)$/;
    return ipRegex.test(input);
}

export function parseMultipleInput(input) {
    return input
        .split(/[\s,]+/)     // split by comma or whitespace
        .map(ip => ip.trim())
        .filter(ip => ip.length > 0);
}


export function createResultCard() {
    const section = document.createElement("div");
    section.className = "result-section";

    const loading = document.createElement("div");
    loading.className = "loading";
    loading.textContent = "Loading...";
    section.appendChild(loading);

    const content = document.createElement("div");
    content.className = "content";
    section.appendChild(content);

    return section;
}

export function resetContainers() {
    ["vtResult", "abuseResult", "haResult", "alienResult"].forEach(id => {
        const section = document.getElementById(id);
        section.style.display = "none";
        section.querySelector(".content").innerHTML = "";
        section.querySelector(".loading").hidden = true;
    });
}


export function verdictColor(label) {
    if (!label) return "gray";
    return label.toLowerCase().includes("suspicious") ? "orange" : "red";
}



// Init setup on popup load

document.addEventListener("DOMContentLoaded", () => {
    setupLookupButton();
    setupCopyAllButton();
    setupOpenAllLinksButton();
});


const observer = new MutationObserver(() => {
    const links = document.querySelectorAll(".external-link");
    const actions = document.getElementById("actionButtonsContainer");
    if (links.length > 0) {
        actions.style.display = "flex";
    }
});

observer.observe(document.body, { childList: true, subtree: true });
