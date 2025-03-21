document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".check-file-btn").forEach(button => {
        button.addEventListener("click", function () {
            const fileHash = this.dataset.hash;
            const rowIndex = this.dataset.index;
            checkFileHash(fileHash, rowIndex);
        });
    });
});

function checkFileHash(fileHash, rowIndex) {
    console.log("CLICK");
    const resultRow = document.getElementById(`file-result-${rowIndex}`);
    const resultSpan = document.getElementById(`vt-file-result-${rowIndex}`);

    // Show the result row and indicate processing
    resultRow.style.display = "table-row";
    resultSpan.innerHTML = `<span style="color: var(--text-color);">⏳ Scanning... (this may take a few minutes)</span>`;

    // Send request to Flask backend
    fetch("/check_file_hash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash: fileHash })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            resultSpan.innerHTML = `<span style="color: var(--danger-color); font-weight: bold;">❌ Error: ${data.error}</span>`;
            return;
        }

        if (data.message === "This file has not been seen before") {
            resultSpan.innerHTML = `
                <span style="color: var(--info-color); font-weight: bold;"> This file has not been seen before by VirusTotal.</span>
            `;
            return;
        }

        // Determine colors based on results
        const malColor = data.malicious > 0 ? "var(--danger-color)" : "var(--success-color)";
        const susColor = data.suspicious > 0 ? "var(--warning-color)" : "var(--success-color)";
        const undetectedColor = data.undetected > 0 ? "var(--info-color)" : "var(--border-color)";

        // Display results with color-coded text
        resultSpan.innerHTML = `
            <div style="padding-top: 8px; padding-bottom: 8px; display: flex; justify-content: center; gap: 12px; flex-wrap: wrap;">
                <span class="badge bg-danger" style="font-size: 14px; padding: 6px 12px;">⚠️ Malicious: ${data.malicious}</span>
                <span class="badge bg-warning" style="font-size: 14px; padding: 6px 12px;">❓ Suspicious: ${data.suspicious}</span>
                <span class="badge bg-success" style="font-size: 14px; padding: 6px 12px;">✅ Undetected: ${data.undetected}</span>
            </div>
            <div style="margin-top: 8px; text-align: center;">
                <a href="${data.vt_link}" target="_blank" class="btn btn-sm btn-outline-primary">🔗 View on VirusTotal</a>
            </div>
        `;
    })
    .catch(error => {
        resultSpan.innerHTML = `<span style="color: var(--danger-color); font-weight: bold;">❌ Failed to fetch results.</span>`;
    });
}
