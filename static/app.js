"use strict";

// --- helpers ---------------------------------------------------------------

async function postJSON(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.json();
}

function debounce(fn, delay) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), delay);
  };
}

const SCORE_COLORS = ["#ff5a5a", "#ff8c42", "#ffb020", "#37c978", "#2fe3a0"];
const PROFILE_LABELS = {
  online_throttled: "Online, rate-limited (100/s)",
  online_unthrottled: "Online, no lockout (10k/s)",
  offline_slow_hash: "Offline slow hash / bcrypt (10k/s)",
  offline_fast_hash: "Offline fast hash / GPU rig (10B/s)",
};

// --- strength analysis -----------------------------------------------------

const analyzeInput = document.getElementById("analyze-input");
const analyzeResult = document.getElementById("analyze-result");
const meterBar = document.getElementById("meter-bar");
const scoreLabel = document.getElementById("score-label");
const entropyLine = document.getElementById("entropy-line");
const warnings = document.getElementById("warnings");
const suggestions = document.getElementById("suggestions");
const crackBody = document.getElementById("crack-body");

async function runAnalysis() {
  const password = analyzeInput.value;
  if (!password) {
    analyzeResult.classList.add("hidden");
    return;
  }

  const data = await postJSON("/api/analyze", { password });
  const s = data.strength;
  const c = data.crack;

  analyzeResult.classList.remove("hidden");

  meterBar.style.width = ((s.score + 1) / 5) * 100 + "%";
  meterBar.style.background = SCORE_COLORS[s.score] || SCORE_COLORS[0];

  scoreLabel.textContent = s.label + " (" + s.score + "/4)";
  entropyLine.textContent =
    " — " + s.entropy_bits + " bits of entropy, pool " + s.pool_size;

  warnings.innerHTML = "";
  s.warnings.forEach((w) => {
    const li = document.createElement("li");
    li.textContent = w;
    warnings.appendChild(li);
  });

  suggestions.innerHTML = "";
  s.suggestions.forEach((sg) => {
    const li = document.createElement("li");
    li.textContent = sg;
    suggestions.appendChild(li);
  });

  crackBody.innerHTML = "";
  Object.keys(c.human_by_profile).forEach((profile) => {
    const tr = document.createElement("tr");
    const label = document.createElement("td");
    const time = document.createElement("td");
    label.textContent = PROFILE_LABELS[profile] || profile;
    time.textContent = c.human_by_profile[profile];
    tr.appendChild(label);
    tr.appendChild(time);
    crackBody.appendChild(tr);
  });
}

analyzeInput.addEventListener("input", debounce(runAnalysis, 250));

document.getElementById("toggle-reveal").addEventListener("change", (e) => {
  analyzeInput.type = e.target.checked ? "text" : "password";
});

// --- hashing ---------------------------------------------------------------

const hashInput = document.getElementById("hash-input");
const hashOutput = document.getElementById("hash-output");
const digestAlgo = document.getElementById("digest-algo");

document.querySelectorAll('input[name="hash-mode"]').forEach((radio) => {
  radio.addEventListener("change", () => {
    const mode = document.querySelector('input[name="hash-mode"]:checked').value;
    digestAlgo.disabled = mode !== "digest";
  });
});

document.getElementById("hash-btn").addEventListener("click", async () => {
  const text = hashInput.value;
  const mode = document.querySelector('input[name="hash-mode"]:checked').value;
  const payload = { text, mode };
  if (mode === "digest") payload.algorithm = digestAlgo.value;

  const data = await postJSON("/api/hash", payload);
  hashOutput.classList.remove("hidden");
  hashOutput.textContent = data.error ? "Error: " + data.error : data.result;
});

// --- verify ----------------------------------------------------------------

document.getElementById("verify-btn").addEventListener("click", async () => {
  const password = document.getElementById("verify-password").value;
  const stored = document.getElementById("verify-stored").value;
  const out = document.getElementById("verify-output");

  const data = await postJSON("/api/verify", { password, stored });
  out.classList.remove("hidden");
  if (data.error) {
    out.textContent = "Error: " + data.error;
    out.className = "output-inline bad";
  } else if (data.match) {
    out.textContent = "✓ Match — the password matches the stored hash.";
    out.className = "output-inline ok";
  } else {
    out.textContent = "✗ No match.";
    out.className = "output-inline bad";
  }
});
