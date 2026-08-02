const API_URL = "http://127.0.0.1:8000";

let severityChart = null;
let pieChart = null;

// ===============================
// Load Dashboard Statistics
// ===============================
async function loadDashboard() {

    try {

        const response = await fetch(`${API_URL}/dashboard`);
        const data = await response.json();

        // Dashboard Cards
        document.getElementById("totalPackets").innerText = data.total_packets;
        document.getElementById("totalAlerts").innerText = data.total_alerts;
        document.getElementById("criticalAlerts").innerText = data.critical_alerts;
        document.getElementById("highAlerts").innerText = data.high_alerts;
        document.getElementById("mediumAlerts").innerText = data.medium_alerts;
        document.getElementById("lowAlerts").innerText = data.low_alerts;

        // Destroy previous charts
        if (severityChart) {
            severityChart.destroy();
        }

        if (pieChart) {
            pieChart.destroy();
        }

        // Severity Bar Chart
        severityChart = new Chart(
            document.getElementById("severityChart"),
            {
                type: "bar",
                data: {
                    labels: ["Critical", "High", "Medium", "Low"],
                    datasets: [{
                        label: "Alerts",
                        data: [
                            data.critical_alerts,
                            data.high_alerts,
                            data.medium_alerts,
                            data.low_alerts
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            }
        );

        // Pie Chart
        pieChart = new Chart(
            document.getElementById("pieChart"),
            {
                type: "pie",
                data: {
                    labels: ["Critical", "High", "Medium", "Low"],
                    datasets: [{
                        data: [
                            data.critical_alerts,
                            data.high_alerts,
                            data.medium_alerts,
                            data.low_alerts
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            }
        );

    }

    catch (error) {

        console.error("Dashboard Error:", error);

    }

}

// ===============================
// Load Alerts
// ===============================
async function loadAlerts() {

    try {

        const response = await fetch(`${API_URL}/alerts`);
        const alerts = await response.json();

        const table = document.getElementById("alertsTable");

        table.innerHTML = "";

        alerts
            .slice()
            .reverse()
            .slice(0, 10)
            .forEach(alert => {

                table.innerHTML += `
                    <tr>
                        <td>${new Date(alert.timestamp).toLocaleString()}</td>
                        <td>${alert.source_ip}</td>
                        <td>${alert.attack_type}</td>
                        <td>${alert.severity}</td>
                    </tr>
                `;

            });

    }

    catch (error) {

        console.error("Alerts Error:", error);

    }

}

// ===============================
// Load Packets
// ===============================
async function loadPackets() {

    try {

        const response = await fetch(`${API_URL}/packets`);
        const packets = await response.json();

        const table = document.getElementById("packetsTable");

        table.innerHTML = "";

        packets
            .slice()
            .reverse()
            .slice(0, 10)
            .forEach(packet => {

                table.innerHTML += `
                    <tr>
                        <td>${new Date(packet.timestamp).toLocaleString()}</td>
                        <td>${packet.source_ip}</td>
                        <td>${packet.destination_ip}</td>
                        <td>${packet.protocol}</td>
                    </tr>
                `;

            });

    }

    catch (error) {

        console.error("Packets Error:", error);

    }

}

// ===============================
// Welcome User
// ===============================
const username = localStorage.getItem("username");

if (username) {

    document.getElementById("welcomeUser").innerHTML =
        "Welcome, " + username;

}

// ===============================
// Logout
// ===============================
document.getElementById("logout").addEventListener("click", function () {

    localStorage.removeItem("username");

    window.location.href = "login.html";

});

// ===============================
// Refresh Dashboard
// ===============================
async function refreshDashboard() {

    await loadDashboard();

    await loadAlerts();

    await loadPackets();

}

// Initial Load
refreshDashboard();

// Refresh every 5 seconds
setInterval(refreshDashboard, 5000);