// =========================================================
// JWT EDITOR - Mouse-triggered update mode
// =========================================================

let savedSignature = "";
let currentAlg = "";
let pendingUpdate = false;   // <-- NEW: Track if edits are waiting
let verificationStatus = null;

// ---------------------------------------------------------
// Helpers
// ---------------------------------------------------------

function base64UrlEncode(input) {
  return btoa(input)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlDecode(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = input.length % 4;
  if (pad) input += '='.repeat(4 - pad);
  try { return atob(input); } catch { return null; }
}

function getHMACAlgo(alg) {
  switch (alg) {
    case "HS256": return CryptoJS.HmacSHA256;
    case "HS384": return CryptoJS.HmacSHA384;
    case "HS512": return CryptoJS.HmacSHA512;
    default: return null; // RSA, ES, none
  }
}

// ---------------------------------------------------------
// Decode JWT into editor
// ---------------------------------------------------------

function autoDecodeJWT() {
  const jwtInput = document.getElementById("jwtInput").value.trim();
  const parts = jwtInput.split(".");
  const headerBox = document.getElementById("decodedHeader");
  const payloadBox = document.getElementById("decodedPayload");

  verificationStatus = document.getElementById("verifyStatus");

  if (parts.length === 3) savedSignature = parts[2];

  if (parts.length !== 3) {
    headerBox.value = "";
    payloadBox.value = "";
    if (verificationStatus) verificationStatus.textContent = "❌ Invalid JWT format";
    return;
  }

  const decodedHeader = base64UrlDecode(parts[0]);
  const decodedPayload = base64UrlDecode(parts[1]);

  if (!decodedHeader || !decodedPayload) {
    if (verificationStatus) verificationStatus.textContent = "❌ Base64 decode error";
    return;
  }

  try {
    const headerObj = JSON.parse(decodedHeader);
    const payloadObj = JSON.parse(decodedPayload);

    headerBox.value = JSON.stringify(headerObj, null, 2);
    payloadBox.value = JSON.stringify(payloadObj, null, 2);

    currentAlg = headerObj.alg || "";

    liveVerify(jwtInput);

  } catch {
    if (verificationStatus) verificationStatus.textContent = "❌ Invalid JSON in header/payload";
  }
}

// ---------------------------------------------------------
// Signature verification
// ---------------------------------------------------------

function liveVerify(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) return;

  const [header, payload, signature] = parts;

  const decodedHeader = JSON.parse(atob(header.replace(/-/g, "+").replace(/_/g, "/")));
  const alg = decodedHeader.alg;

  if (alg === "none") {
    verificationStatus.textContent = "✔ Valid (alg=none)";
    return;
  }

  const hmacAlgo = getHMACAlgo(alg);
  const secret = document.getElementById("editSecret").value.trim();

  if (!hmacAlgo) {
    verificationStatus.textContent = "⚠ Cannot verify RSA/ES signatures";
    return;
  }

  if (!secret) {
    verificationStatus.textContent = "⚠ Provide secret key to verify";
    return;
  }

  const expectedSig = CryptoJS.enc.Base64.stringify(
    hmacAlgo(header + "." + payload, secret)
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  verificationStatus.textContent = 
    expectedSig === signature ? "✔ Signature valid" : "❌ Signature invalid";
}

// ---------------------------------------------------------
// JWT Regeneration (Triggered by mouse)
// ---------------------------------------------------------

function updateJWTFromEdits() {
  const headerBox = document.getElementById("decodedHeader").value.trim();
  const payloadBox = document.getElementById("decodedPayload").value.trim();
  const secret = document.getElementById("editSecret").value.trim();
  const output = document.getElementById("encodedResult");
  const jwtInput = document.getElementById("jwtInput");

  try {
    const header = JSON.parse(headerBox);
    const payload = JSON.parse(payloadBox);

    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));

    const data = encodedHeader + "." + encodedPayload;
    let finalJWT = data;

    currentAlg = header.alg;

    // alg: none → no signature
    if (header.alg === "none") {
      finalJWT = data + ".";
    }

    else {
      const hmacAlgo = getHMACAlgo(header.alg);

      if (!hmacAlgo) {
        // RSA → keep original signature
        finalJWT = data + "." + savedSignature;
      }

      else if (secret) {
        const hmac = hmacAlgo(data, secret);
        const newSig = CryptoJS.enc.Base64.stringify(hmac)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
        finalJWT = data + "." + newSig;
      }

      else {
        finalJWT = data + "." + savedSignature;
      }
    }

    jwtInput.value = finalJWT;
    output.textContent = finalJWT;

    liveVerify(finalJWT);

  } catch {
    output.textContent = "Invalid JSON.";
  }
}

// ---------------------------------------------------------
// Trigger updates only when mouse enters JWT field
// ---------------------------------------------------------

function triggerUpdateOnMouseEnter() {
  if (pendingUpdate) {
    updateJWTFromEdits();
    pendingUpdate = false;
  }
}

// ---------------------------------------------------------
// Load Demo button
// ---------------------------------------------------------

function loadTestJWT() {
  const demoJWT =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJ1c2VyIjoiYWRtaW4ifQ." +
    "qK7qEqLJHX_8JoECnKoMsMo8CtX3oywecGe0NSK5pCg";

  const secret = "admin";

  document.getElementById("jwtInput").value = demoJWT;
  document.getElementById("editSecret").value = secret;

  savedSignature = demoJWT.split(".")[2];

  autoDecodeJWT();
}

// ---------------------------------------------------------
// Clipboard
// ---------------------------------------------------------

function copyToClipboard() {
  const text = document.getElementById("encodedResult").textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("copyButton");
    const old = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = old), 2000);
  });
}

// ---------------------------------------------------------
// Event Listeners
// ---------------------------------------------------------

// Decode JWT when pasted
document.getElementById("jwtInput").addEventListener("input", autoDecodeJWT);

// Editing → mark update as pending
document.getElementById("decodedHeader").addEventListener("input", () => pendingUpdate = true);
document.getElementById("decodedPayload").addEventListener("input", () => pendingUpdate = true);
document.getElementById("editSecret").addEventListener("input", () => pendingUpdate = true);

// Mouse over JWT input → apply updates
document.getElementById("jwtInput").addEventListener("mouseenter", triggerUpdateOnMouseEnter);

// Buttons
document.getElementById("loadDemoBtn").addEventListener("click", loadTestJWT);
document.getElementById("copyButton").addEventListener("click", copyToClipboard);
