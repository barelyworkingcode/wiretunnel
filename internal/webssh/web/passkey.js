"use strict";

// Shared passkey (WebAuthn) helpers used by both the terminal page (app.js) and
// the session console (console.js). enroll() and signIn() resolve once the
// server has started a session cookie; the caller decides what to do next
// (open the terminal, or load the session list). Exposed as window.Passkey.

(function () {
  // --- base64url <-> ArrayBuffer helpers --------------------------------
  // The server speaks the WebAuthn JSON dialect (challenge / id fields are
  // base64url strings); the browser credential API speaks ArrayBuffers.

  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad) s += "=".repeat(4 - pad);
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function postJSON(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
    return res.json();
  }

  // --- passkey flows ----------------------------------------------------

  async function enroll() {
    const { publicKey } = await postJSON("/api/register/begin", {});
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    publicKey.user.id = b64urlToBuf(publicKey.user.id);
    (publicKey.excludeCredentials || []).forEach((c) => (c.id = b64urlToBuf(c.id)));

    const cred = await navigator.credentials.create({ publicKey });
    await postJSON("/api/register/finish", {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToB64url(cred.response.attestationObject),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      },
    });
  }

  async function signIn() {
    const { publicKey } = await postJSON("/api/login/begin", {});
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    (publicKey.allowCredentials || []).forEach((c) => (c.id = b64urlToBuf(c.id)));

    const cred = await navigator.credentials.get({ publicKey });
    await postJSON("/api/login/finish", {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        signature: bufToB64url(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
      },
    });
  }

  window.Passkey = { enroll, signIn };
})();
