const API_URL = "http://127.0.0.1:8000";

const loginForm = document.getElementById("loginForm");

if (loginForm) {

    loginForm.addEventListener("submit", async function(event) {

        event.preventDefault();

        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        const response = await fetch(`${API_URL}/login`, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                username,
                password
            })

        });

        const result = await response.json();

        const message = document.getElementById("message");

        if (response.ok) {

            message.style.color = "lightgreen";
            message.innerHTML = "✅ Login Successful!";

            setTimeout(() => {
                window.location.href = "dashboard.html";
            }, 1000);

        } else {

            message.style.color = "red";
            message.innerHTML = result.detail;

        }

    });

}