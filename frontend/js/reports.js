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