"use strict";
for (const input of document.querySelectorAll('input[type="password"]')) {
  const wrapper = document.createElement("span");
  wrapper.className = "password-entry";
  input.before(wrapper);
  const button = document.createElement("button");
  button.type = "button";
  button.className = "secondary password-toggle";
  button.setAttribute("aria-controls", input.id);
  const icon = document.createElement("span");
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = "👁";
  button.append(icon);
  function reveal(visible) {
    input.type = visible ? "text" : "password";
    button.setAttribute("aria-pressed", String(visible));
    button.setAttribute("aria-label", "Show password");
    button.title = visible ? "Hide password" : "Show password";
  }
  button.addEventListener("click", () => reveal(input.type === "password"));
  input.form?.addEventListener("submit", () => reveal(false), true);
  input.closest("dialog")?.addEventListener("close", () => reveal(false));
  wrapper.append(input, button);
  reveal(false);
}
