const API_URL = "http://127.0.0.1:8000";

// ----------------------------
// Load Live Packets
// ----------------------------
async function loadPackets() {

    try {

        const response = await fetch(`${API_URL}/packets`);

        const packets = await response.json();

        const table = document.getElementById("livePackets");

        table.innerHTML = "";

        packets
            .slice(-10)
            .reverse()
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

    catch(error){

        console.error("Packet Error:", error);

    }

}

// ----------------------------
// Load Live Alerts
// ----------------------------
async function loadAlerts() {

    try {

        const response = await fetch(`${API_URL}/alerts`);

        const alerts = await response.json();

        const table = document.getElementById("liveAlerts");

        table.innerHTML = "";

        alerts
            .slice(-10)
            .reverse()
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

    catch(error){

        console.error("Alert Error:", error);

    }

}

// ----------------------------
// Refresh Every 5 Seconds
// ----------------------------
function refresh(){

    loadPackets();

    loadAlerts();

}

refresh();

setInterval(refresh,5000);