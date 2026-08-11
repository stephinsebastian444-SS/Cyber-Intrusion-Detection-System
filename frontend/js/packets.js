const API_URL = "http://127.0.0.1:8000";

async function loadPackets() {

    try {

        const response = await fetch(`${API_URL}/packets`);

        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const packets = await response.json();

        console.log("Packets received:", packets);

        const table = document.getElementById("packetTable");

        if (!table) {
            console.error("ERROR: packetTable element not found.");
            return;
        }

        table.innerHTML = "";

        if (packets.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="8">
                        No packets captured yet.
                    </td>
                </tr>
            `;

            return;
        }

        packets
            .slice()
            .reverse()
            .forEach(packet => {

                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>${packet.id}</td>

                    <td>
                        ${new Date(packet.timestamp).toLocaleString()}
                    </td>

                    <td>${packet.source_ip}</td>

                    <td>${packet.destination_ip}</td>

                    <td>${packet.protocol}</td>

                    <td>${packet.source_port ?? "-"}</td>

                    <td>${packet.destination_port ?? "-"}</td>

                    <td>${packet.packet_size}</td>
                `;

                table.appendChild(row);

            });

    } catch (error) {

        console.error(
            "Failed to load packets:",
            error
        );

    }
}


// Initial load
loadPackets();


// Refresh every 5 seconds
setInterval(loadPackets, 5000);