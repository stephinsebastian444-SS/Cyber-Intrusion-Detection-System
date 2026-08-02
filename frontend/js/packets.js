const API_URL = "http://127.0.0.1:8000";

async function loadPackets() {

    const response = await fetch(`${API_URL}/packets`);

    const packets = await response.json();

    const table = document.getElementById("packetTable");

    table.innerHTML = "";

    packets.forEach(packet => {

        table.innerHTML += `

        <tr>

            <td>${packet.id}</td>

            <td>${new Date(packet.timestamp).toLocaleString()}</td>

            <td>${packet.source_ip}</td>

            <td>${packet.destination_ip}</td>

            <td>${packet.protocol}</td>

            <td>${packet.source_port ?? "-"}</td>

            <td>${packet.destination_port ?? "-"}</td>

            <td>${packet.packet_size}</td>

        </tr>

        `;

    });

}

loadPackets();