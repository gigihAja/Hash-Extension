export function setupOpenAllLinksButton() {
    const openBtn = document.getElementById("openAllLinksBtn");
    if (!openBtn) return;

    openBtn.addEventListener("click", () => {
        const links = document.querySelectorAll("a.external-link");
        if (links.length === 0) {
            alert("No links found to open.");
            return;
        }

        links.forEach(link => {
            const url = link.getAttribute("href");
            if (url && url.startsWith("http")) {
                chrome.tabs.create({ url });
            }
        });
    });
}
