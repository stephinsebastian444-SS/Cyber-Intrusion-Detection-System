const API = "http://127.0.0.1:8000";

async function loadSummary(){

    const response = await fetch(`${API}/dashboard`);

    const data = await response.json();

    document.getElementById("packets").innerHTML = data.total_packets;

    document.getElementById("alerts").innerHTML = data.total_alerts;

    document.getElementById("critical").innerHTML = data.critical_alerts;

    document.getElementById("high").innerHTML = data.high_alerts;

    document.getElementById("medium").innerHTML = data.medium_alerts;

    document.getElementById("low").innerHTML = data.low_alerts;

}

loadSummary();

// ----------------------------
// Export Alerts CSV
// ----------------------------
document.getElementById("exportAlerts").onclick = async function () {

    const response = await fetch(`${API}/alerts`);

    const alerts = await response.json();

    let csv = "Time,Source IP,Attack Type,Severity,Risk Score\n";

    alerts.forEach(alert => {

        csv += `${alert.timestamp},${alert.source_ip},${alert.attack_type},${alert.severity},${alert.risk_score}\n`;

    });

    const blob = new Blob([csv], { type: "text/csv" });

    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");

    a.href = url;

    a.download = "alerts.csv";

    a.click();

};

// ----------------------------
// Export Packets CSV
// ----------------------------
document.getElementById("exportPackets").onclick = async function () {

    const response = await fetch(`${API}/packets`);

    const packets = await response.json();

    let csv = "Time,Source IP,Destination IP,Protocol,Packet Size\n";

    packets.forEach(packet => {

        csv += `${packet.timestamp},${packet.source_ip},${packet.destination_ip},${packet.protocol},${packet.packet_size}\n`;

    });

    const blob = new Blob([csv], { type: "text/csv" });

    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");

    a.href = url;

    a.download = "packets.csv";

    a.click();

};