const API_URL = "http://127.0.0.1:8000";

const registerForm = document.getElementById("registerForm");

if (registerForm) {

    registerForm.addEventListener("submit", async function (event) {

        event.preventDefault();

        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        const response = await fetch(`${API_URL}/users`, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                username: username,
                password: password
            })

        });

        const result = await response.json();

        const message = document.getElementById("message");

        if (response.ok) {
            message.innerHTML = "✅ User registered successfully!";
            message.style.color = "lightgreen";
            registerForm.reset();

            setTimeout(() => {

                window.location.href = "login.html";
            }, 1000);
        
        }else {
            message.innerHTML = result.detail || "Registration failed.";
            message.style.color = "red";
        }

    });

}