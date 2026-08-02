const API_URL = "http://127.0.0.1:8000";

async function loadPackets() {

    const response = await fetch(`${API_URL}/packets`);

    const packets = await response.json();

    const table = document.getElementById("livePackets");

    table.innerHTML = "";

    packets.slice(-10).reverse().forEach(packet => {

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

async function loadAlerts() {

    const response = await fetch(`${API_URL}/alerts`);

    const alerts = await response.json();

    const table = document.getElementById("liveAlerts");

    table.innerHTML = "";

    alerts.slice(-10).reverse().forEach(alert => {

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

function refresh() {

    loadPackets();

    loadAlerts();

}

refresh();

setInterval(refresh, 5000);