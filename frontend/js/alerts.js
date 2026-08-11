const API = "http://127.0.0.1:8000";

// ===============================
// Load Alerts
// ===============================

async function loadAlerts() {

    try {

        const response = await fetch(`${API}/alerts`);

        if (!response.ok) {
            throw new Error("Failed to load alerts");
        }

        const alerts = await response.json();

        const table = document.getElementById("alertTable");

        if (!table) {
            console.error("alertTable element not found");
            return;
        }

        table.innerHTML = "";

        if (alerts.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="7">
                        No alerts detected.
                    </td>
                </tr>
            `;

            return;
        }

        alerts
            .slice()
            .reverse()
            .forEach(alert => {

                let severityClass = "";

                if (alert.severity === "Critical") {
                    severityClass = "critical";
                }
                else if (alert.severity === "High") {
                    severityClass = "high";
                }
                else if (alert.severity === "Medium") {
                    severityClass = "medium";
                }
                else if (alert.severity === "Low") {
                    severityClass = "low";
                }

                table.innerHTML += `

                    <tr>

                        <td>
                            ${alert.id}
                        </td>

                        <td>
                            ${new Date(alert.timestamp).toLocaleString()}
                        </td>

                        <td>
                            ${alert.source_ip}
                        </td>

                        <td>
                            ${alert.attack_type}
                        </td>

                        <td>
                            <span class="severity-badge ${severityClass}">
                                ${alert.severity}
                            </span>
                        </td>

                        <td>
                            ${alert.risk_score}
                        </td>

                        <td>

                            <button
                                class="delete-button"
                                onclick="deleteAlert(${alert.id})"
                            >
                                Delete
                            </button>

                        </td>

                    </tr>

                `;

            });

    }

    catch (error) {

        console.error("Alerts Error:", error);

    }

}


// ===============================
// Delete Alert
// ===============================

async function deleteAlert(id) {

    const confirmed = confirm(
        "Are you sure you want to delete this alert?"
    );

    if (!confirmed) {
        return;
    }

    try {

        const response = await fetch(
            `${API}/alerts/${id}`,
            {
                method: "DELETE"
            }
        );

        if (!response.ok) {

            throw new Error(
                "Failed to delete alert"
            );

        }

        await loadAlerts();

    }

    catch (error) {

        console.error(
            "Delete Alert Error:",
            error
        );

        alert(
            "Unable to delete the alert."
        );

    }

}


// ===============================
// Initial Load
// ===============================

loadAlerts();