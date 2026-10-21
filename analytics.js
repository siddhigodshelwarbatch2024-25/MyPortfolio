(() => {
    const utmSource = new URLSearchParams(window.location.search).get("utm_source") || "";
    fetch("/api/analytics/visit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        keepalive: true,
        body: JSON.stringify({
            page: window.location.pathname,
            referrer: document.referrer,
            utmSource
        })
    })
        .then((response) => response.ok ? response.json() : null)
        .then((data) => {
            const count = document.getElementById("visitor-count");
            if (count && data?.uniqueVisitors !== undefined) {
                count.textContent = Number(data.uniqueVisitors).toLocaleString();
            }
        })
        .catch(() => {
            const count = document.getElementById("visitor-count");
            if (count) count.textContent = "Unavailable";
        });
})();