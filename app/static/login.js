"use strict";
const loginForm = document.getElementById("login-form");
const loginButton = document.getElementById("login-button");
const loginStatus = document.getElementById("login-status");

async function checkOwner() {
  try {
    const response = await fetch("/api/auth/status", {cache: "no-store"});
    if (!response.ok) throw new Error("Could not check local account setup.");
    const status = await response.json();
    document.getElementById("setup-message").hidden = status.configured;
    loginForm.hidden = !status.configured;
  } catch (error) { loginStatus.textContent = error.message; }
}
loginForm.addEventListener("submit", async (event) => {
  event.preventDefault(); loginButton.disabled = true; loginStatus.textContent = "Signing in locally…";
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST", cache: "no-store", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-Sentinel-Import": "1"},
      body: JSON.stringify({username: document.getElementById("username").value,
                            password: document.getElementById("password").value}),
    });
    document.getElementById("password").value = "";
    if (!response.ok) {
      const body = await response.json();
      throw new Error(typeof body.detail === "string" ? body.detail : "Sign-in failed.");
    }
    window.location.replace("/");
  } catch (error) { loginStatus.textContent = error.message; }
  finally { loginButton.disabled = false; }
});
checkOwner();
