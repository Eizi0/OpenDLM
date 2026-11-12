/* Small progressive enhancements for the sign-in pages. Everything works without JavaScript. */
(function () {
  "use strict";

  // Show / hide a password field.
  document.querySelectorAll("[data-toggle-password]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.togglePassword);
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? btn.dataset.hide : btn.dataset.show;
      btn.setAttribute("aria-pressed", show ? "true" : "false");
    });
  });

  // Caps Lock warning.
  document.querySelectorAll("input[type=password]").forEach(function (input) {
    var hint = document.querySelector('[data-caps-for="' + input.id + '"]');
    if (!hint) return;
    function update(e) { hint.hidden = !(e.getModifierState && e.getModifierState("CapsLock")); }
    input.addEventListener("keydown", update);
    input.addEventListener("keyup", update);
    input.addEventListener("blur", function () { hint.hidden = true; });
  });

  // Password strength meter (setup page): a rough guide, the server enforces the real rule.
  var pw = document.querySelector("[data-strength]");
  if (pw) {
    var meter = document.getElementById("strength-meter");
    var label = document.getElementById("strength-label");
    var names = (label && label.dataset.names || "").split("|");
    pw.addEventListener("input", function () {
      var v = pw.value, score = 0;
      if (v.length >= 12) score++;
      if (v.length >= 16) score++;
      if (/[a-z]/.test(v) && /[A-Z0-9]/.test(v)) score++;
      if (/[^A-Za-z0-9]/.test(v) || v.length >= 22) score++;
      if (v.length < 12) score = Math.min(score, 1);
      if (!v) score = 0;
      meter.className = "meter s" + score;
      label.textContent = score ? names[score - 1] || "" : "";
    });
  }

  // Second step: switch between an authenticator code and a recovery code, submit when 6 digits are typed.
  var code = document.getElementById("code");
  if (code) {
    var form = code.form, toggle = document.getElementById("recovery-toggle"), recovery = false;
    code.addEventListener("input", function () {
      if (recovery) return;
      var digits = code.value.replace(/\s+/g, "");
      if (/^\d{6}$/.test(digits)) { code.value = digits; form.requestSubmit ? form.requestSubmit() : form.submit(); }
    });
    if (toggle) {
      toggle.addEventListener("click", function () {
        recovery = !recovery;
        code.classList.toggle("recovery", recovery);
        code.setAttribute("inputmode", recovery ? "text" : "numeric");
        code.setAttribute("placeholder", recovery ? "xxxxx-xxxxx" : "000 000");
        code.value = "";
        toggle.textContent = recovery ? toggle.dataset.useApp : toggle.dataset.useRecovery;
        document.getElementById("code-label").textContent = recovery ? toggle.dataset.labelRecovery : toggle.dataset.labelApp;
        code.focus();
      });
    }
  }

  // Prevent double submits, and restore the button if the page is shown again from the history.
  document.querySelectorAll("form[data-once]").forEach(function (f) {
    f.addEventListener("submit", function () {
      var b = f.querySelector("button[type=submit]");
      if (b && !b.disabled) { b.dataset.label = b.textContent; b.textContent = b.dataset.busy || b.textContent; setTimeout(function () { b.disabled = true; }, 0); }
    });
  });
  window.addEventListener("pageshow", function () {
    document.querySelectorAll("form[data-once] button[type=submit]").forEach(function (b) {
      b.disabled = false; if (b.dataset.label) b.textContent = b.dataset.label;
    });
  });
})();
