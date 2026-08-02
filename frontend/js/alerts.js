const API = "http://127.0.0.1:8000";

loadAlerts();

async function loadAlerts(){

    const response = await fetch(`${API}/alerts`);

    const alerts = await response.json();

    const table = document.getElementById("alertTable");

    table.innerHTML = "";

    alerts.forEach(alert=>{

        table.innerHTML += `

        <tr>

            <td>${alert.id}</td>

            <td>${new Date(alert.timestamp).toLocaleString()}</td>

            <td>${alert.source_ip}</td>

            <td>${alert.attack_type}</td>

            <td>${alert.severity}</td>

            <td>${alert.risk_score}</td>

            <td>

                <button onclick="deleteAlert(${alert.id})">

                    Delete

                </button>

            </td>

        </tr>

        `;

    });

}

async function deleteAlert(id){

    if(!confirm("Delete this alert?"))
        return;

    await fetch(`${API}/alerts/${id}`,{

        method:"DELETE"

    });

    loadAlerts();

}