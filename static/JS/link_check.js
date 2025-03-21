document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".check-link-btn").forEach(button => {
        button.addEventListener("click", function () {
            const link = this.dataset.link;
            const rowIndex = this.dataset.index;
            checkLink(link, rowIndex);
        });
    });
});

function checkLink(link, rowIndex) {
    const resultRow = document.getElementById(`result-link-${rowIndex}`);
    const resultSpan = document.getElementById(`vt-link-result-${rowIndex}`);

    // Show the result row and indicate processing
    resultRow.style.display = "table-row";
    resultSpan.innerHTML = `<span style="color: var(--text-color);">⏳ Scanning... (this may take a few minutes)</span>`;

    // Send request to Flask backend
    fetch("/check_url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: link })
    })
    .then(response => response.json())
    .then(data => {
        if (data["VT-Error"]) {
            resultSpan.innerHTML = `<span style="color: var(--danger-color); font-weight: bold;">❌ Error: ${data["VT-Error"]}</span>`;
            return;
        }

        // Determine colors based on results
        const malColor = data["VT-Malicious"] > 0 ? "var(--danger-color)" : "var(--success-color)";
        const susColor = data["VT-Suspicious"] > 0 ? "var(--warning-color)" : "var(--success-color)";
        const cleanColor = data["VT-Clean"] > 0 ? "var(--success-color)" : "var(--border-color)";

        // Display results with color-coded text
        resultSpan.innerHTML = `
            <div style="padding-top: 8px; padding-bottom: 8px; display: flex; justify-content: center; align-items: center; gap: 12px; flex-wrap: wrap;">
                <span class="badge bg-danger" style="font-size: 14px; padding: 6px 12px;">⚠️ Malicious: ${data["VT-Malicious"]}</span>
                <span class="badge bg-warning" style="font-size: 14px; padding: 6px 12px;">❓ Suspicious: ${data["VT-Suspicious"]}</span>
                <span class="badge bg-success" style="font-size: 14px; padding: 6px 12px;">✅ Clean: ${data["VT-Clean"]}</span>
            </div>
            <div style="margin-top: 8px; text-align: center;">
                <a href="https://www.virustotal.com/gui/url/${data["VT-Hash"]}" target="_blank" class="btn btn-sm btn-outline-primary">🔗 View on VirusTotal</a>
            </div>
        `;
    })
    .catch(error => {
        console.error("Fetch error:", error);
        resultSpan.innerHTML = `<span style="color: var(--danger-color); font-weight: bold;">❌ Failed to fetch results.</span>`;
    });
}
