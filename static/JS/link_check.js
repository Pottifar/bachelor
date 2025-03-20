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
    const resultRow = document.getElementById(`result-${rowIndex}`);
    const resultSpan = document.getElementById(`vt-result-${rowIndex}`);

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
            <div style="padding-top: 12px; padding-bottom: 12px;">
                <span style="color: ${malColor}; font-weight: bold;"> Malicious: ${data["VT-Malicious"]}</span> |
                <span style="color: ${susColor}; font-weight: bold;"> Suspicious: ${data["VT-Suspicious"]}</span> |
                <span style="color: ${cleanColor}; font-weight: bold;"> Clean: ${data["VT-Clean"]}</span>
            </div>
        `;
    })
    .catch(error => {
        console.error("Fetch error:", error);
        resultSpan.innerHTML = `<span style="color: var(--danger-color); font-weight: bold;">❌ Failed to fetch results.</span>`;
    });
}
