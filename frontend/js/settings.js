const form = document.getElementById("settingsForm");

form.addEventListener("submit", function(e){

    e.preventDefault();

    localStorage.setItem(
        "interface",
        document.getElementById("interface").value
    );

    localStorage.setItem(
        "sensitivity",
        document.getElementById("sensitivity").value
    );

    localStorage.setItem(
        "refresh",
        document.getElementById("refresh").value
    );

    document.getElementById("message").innerHTML =
        "✅ Settings Saved";

});