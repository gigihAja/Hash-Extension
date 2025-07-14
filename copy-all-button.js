import { state } from "./popup.js";  // pastikan ini ada!

export function setupCopyAllButton() {
    const copyAllBtn = document.getElementById("copyAllBtn");

    copyAllBtn.addEventListener("click", () => {
        const cleanText = (containerId) => {
            const section = document.getElementById(containerId);
            if (!section || section.style.display === "none") return "";

            const container = section.querySelector(".content");
            if (!container) return "";

            const clone = container.cloneNode(true);

            // Hapus loading
            clone.querySelectorAll(".loading").forEach(el => el.remove());

            // Hapus link
            clone.querySelectorAll("a").forEach(a => a.remove());

            // Ganti ul > li
            clone.querySelectorAll("ul").forEach(ul => {
                const items = Array.from(ul.querySelectorAll("li"))
                    .map(li => `- ${li.innerText.trim()}`);
                const block = document.createElement("div");
                block.textContent = items.join("\n");
                ul.replaceWith(block);
            });

            // Ganti <p> & <br> jadi teks biasa
            clone.querySelectorAll("p").forEach(p => {
                const text = document.createTextNode(p.textContent.trim() + "\n");
                p.replaceWith(text);
            });
            clone.querySelectorAll("br").forEach(br => {
                const text = document.createTextNode("\n");
                br.replaceWith(text);
            });

            // Sanitize \n\n → \n
            let text = clone.textContent.trim();
            text = text.replace(/\r/g, "").replace(/\n{2,}/g, "\n");
            return text;
        };




        const vt = cleanText("vtResult");
        const otx = cleanText("alienResult");
        const ha = cleanText("haResult");
        const abuse = cleanText("abuseResult");

        let combined = "";

        if (state.lastInputType === "ip") {
            const sections = [];
            if (vt) sections.push("VirusTotal\n" + vt);
            if (abuse) sections.push("AbuseIPDB\n" + abuse);
            if (!sections.length) return alert("No IP result to copy :(");
            combined = "#IP :\n" + sections.join("\n\n---\n\n");
        }
        else if (state.lastInputType === "hash") {
            const sections = [];
            if (vt) sections.push("VirusTotal:\n" + vt);
            if (otx) sections.push("AlienVault OTX:\n" + otx);
            if (ha) sections.push("Hybrid Analysis:\n" + ha);
            if (!sections.length)
                return alert("No hash result to copy :(");
            combined = "#Hash :\n" + sections.join("\n\n---\n\n");
        }
        else {
            return alert("No result to copy...");
        }

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
}