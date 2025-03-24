document.addEventListener("DOMContentLoaded", function () {
    // Attach event listeners to "Check with VirusTotal" buttons
    document.querySelectorAll(".check-file-btn").forEach(button => {
        button.addEventListener("click", function () {
            const fileHash = this.dataset.hash;
            const rowIndex = this.dataset.index;
            checkFileHash(fileHash, rowIndex);
        });
    });

    // Fetch explanations for suspicious file extensions
    fetch("../static/explanations.json")
        .then(response => response.json())
        .then(explanations => {
            document.querySelectorAll("tbody tr").forEach(row => {
                let extensionCell = row.querySelector("td:nth-child(2)"); // Second column (extension)
                if (extensionCell) {
                    let fileExtension = extensionCell.innerText.trim();

                    // Check if the extension is suspicious
                    if (explanations[fileExtension]) {
                        let warningIcon = document.createElement("span");
                        warningIcon.innerHTML = "⚠️"; // Warning emoji
                        warningIcon.classList.add("tooltip-trigger", "ms-2");
                        warningIcon.setAttribute("data-bs-toggle", "tooltip");
                        warningIcon.setAttribute("data-bs-placement", "top");
                        warningIcon.setAttribute("data-bs-html", "true");
                        warningIcon.setAttribute("data-bs-custom-class", "custom-tooltip");

                        // Get explanation from JSON file
                        let explanation = explanations[fileExtension];
                        warningIcon.setAttribute("title", `<div style='max-width: 250px; padding: 8px; text-align: left; font-size: 14px;'>
                            <h4 style='margin-bottom: 8px; font-size: 16px;'>⚠️ Suspicious File Extension</h4>
                            <p>${explanation}</p>
                        </div>`);

                        extensionCell.appendChild(warningIcon); // Add warning next to extension
                    }
                }
            });

            // Activate Bootstrap tooltips AFTER adding warning icons
            var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
        })
        .catch(error => console.error("Error loading explanations:", error));
});

// Function to check file hash with VirusTotal
function checkFileHash(fileHash, rowIndex) {
    console.log("Checking file hash...");

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

        // Color assignment based on detection results
        const malColor = data.malicious > 0 ? "var(--danger-color)" : "var(--success-color)";
        const susColor = data.suspicious > 0 ? "var(--warning-color)" : "var(--success-color)";
        const undetectedColor = data.undetected > 0 ? "var(--info-color)" : "var(--border-color)";

        // Display results with color-coded badges
        resultSpan.innerHTML = `
            <div style="padding-top: 8px; padding-bottom: 8px; display: flex; justify-content: center; gap: 12px; flex-wrap: wrap;">
                <span class="badge" style="font-size: 14px; padding: 6px 12px; background-color: ${malColor}; color: white;">⚠️ Malicious: ${data.malicious}</span>
                <span class="badge" style="font-size: 14px; padding: 6px 12px; background-color: ${susColor}; color: white;">❓ Suspicious: ${data.suspicious}</span>
                <span class="badge" style="font-size: 14px; padding: 6px 12px; background-color: ${undetectedColor}; color: white;">✅ Undetected: ${data.undetected}</span>
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
