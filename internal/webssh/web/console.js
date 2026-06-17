"use strict";

// Admin console for WebSSH: lists every live session with its connection count
// and busy/idle state, and lets you open (join) or kill any of them. All data
// comes from /api/sessions, which is gated by the same passkey session as the
// terminal. When the visitor is not signed in, the page presents the passkey
// prompt right here (via the shared window.Passkey flows) so they never have to
// detour through the terminal — once unlocked, the session list loads in place.

const summaryEl = document.getElementById("summary");
const statusEl = document.getElementById("status");
const contentEl = document.getElementById("content");
const barEl = document.getElementById("bar");
const scSection = document.getElementById("shortcuts");
const scBody = document.getElementById("sc-body");

const REFRESH_MS = 2000;
let fetching = false;
let killing = new Set(); // ids with an in-flight kill, to disable their button
let refreshTimer = null; // interval handle while signed in; null while gated

let shortcuts = []; // last-loaded shortcut list
let scEditing = null; // {id?, name, command} while the add/edit form is open, else null

// New session: opening a bare "/" makes the server redirect to a fresh
// ?session=<id>, so a new tab lands in its own brand-new shell.
document.getElementById("new-session").addEventListener("click", () => {
  window.open("/", "_blank", "noopener");
});

// "+ Add shortcut" opens a blank form in place of the list.
document.getElementById("sc-add").addEventListener("click", () => {
  scEditing = { id: "", name: "", command: "" };
  renderShortcuts();
});

// formatDuration renders a whole number of seconds compactly (e.g. "5s",
// "3m", "2h 4m", "1d 3h"), showing at most the two largest units.
function formatDuration(sec) {
  sec = Math.max(0, Math.floor(sec));
  if (sec < 60) return sec + "s";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  return `${m}m`;
}

// --- shortcuts ----------------------------------------------------------

// newSessionId mints a fresh, unguessable session id on the client, mirroring
// the server's NewID (16 random bytes, URL-safe base64, no padding). Running a
// shortcut opens a tab at /?session=<id>&run=<shortcutId>; minting the id here
// carries the run parameter through, which the server's bare-"/" redirect to a
// fresh session would otherwise strip.
function newSessionId() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// runShortcut opens a brand-new terminal tab that auto-runs the shortcut. The
// terminal page (app.js) reads ?run=<id>, looks up the stored command, and
// types it at the prompt once the shell is connected.
function runShortcut(id) {
  const url = "/?session=" + newSessionId() + "&run=" + encodeURIComponent(id);
  window.open(url, "_blank", "noopener");
}

async function loadShortcuts() {
  try {
    const res = await fetch("/api/shortcuts", { headers: { Accept: "application/json" } });
    if (res.status === 401) return checkAccess();
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    shortcuts = data.shortcuts || [];
    renderShortcuts();
  } catch (err) {
    // Leave whatever is already on screen; the sessions status line surfaces
    // connectivity problems, and clobbering an open edit form would be worse.
  }
}

function renderShortcuts() {
  scBody.innerHTML = "";
  if (scEditing) {
    scBody.appendChild(buildShortcutForm(scEditing));
    return;
  }
  if (shortcuts.length === 0) {
    const e = document.createElement("div");
    e.className = "sc-empty";
    e.textContent = "No shortcuts yet. Add one to run a command in a click.";
    scBody.appendChild(e);
    return;
  }
  const list = document.createElement("div");
  list.className = "sc-list";
  for (const sc of shortcuts) list.appendChild(buildShortcutCard(sc));
  scBody.appendChild(list);
}

function buildShortcutCard(sc) {
  const card = document.createElement("div");
  card.className = "sc-card";

  const name = document.createElement("div");
  name.className = "sc-name";
  name.textContent = sc.name;
  card.appendChild(name);

  const cmd = document.createElement("div");
  cmd.className = "sc-cmd";
  cmd.textContent = sc.command;
  card.appendChild(cmd);

  const actions = document.createElement("div");
  actions.className = "sc-actions";

  const run = document.createElement("button");
  run.className = "sc-run";
  run.type = "button";
  run.textContent = "Run";
  run.title = "Open a new terminal and run this command";
  run.addEventListener("click", () => runShortcut(sc.id));
  actions.appendChild(run);

  const edit = document.createElement("button");
  edit.className = "sc-edit";
  edit.type = "button";
  edit.textContent = "Edit";
  edit.addEventListener("click", () => {
    scEditing = { id: sc.id, name: sc.name, command: sc.command };
    renderShortcuts();
  });
  actions.appendChild(edit);

  const del = document.createElement("button");
  del.className = "sc-del";
  del.type = "button";
  del.textContent = "Delete";
  del.addEventListener("click", () => deleteShortcut(sc));
  actions.appendChild(del);

  card.appendChild(actions);
  return card;
}

// buildShortcutForm renders the add/edit form for `draft` ({id?, name, command}).
function buildShortcutForm(draft) {
  const form = document.createElement("form");
  form.className = "sc-form";

  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.value = draft.name;
  nameInput.placeholder = "e.g. Git pull";
  nameInput.maxLength = 200;

  const cmdInput = document.createElement("textarea");
  cmdInput.value = draft.command;
  cmdInput.placeholder = "git pull";
  cmdInput.rows = 3;

  form.appendChild(field("Name", nameInput));
  form.appendChild(field("Command", cmdInput));

  const msg = document.createElement("div");
  msg.className = "msg";

  const save = document.createElement("button");
  save.className = "btn-primary";
  save.type = "submit";
  save.textContent = draft.id ? "Save" : "Add shortcut";

  const cancel = document.createElement("button");
  cancel.className = "btn-ghost";
  cancel.type = "button";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", () => {
    scEditing = null;
    renderShortcuts();
  });

  const row = document.createElement("div");
  row.className = "row";
  row.appendChild(save);
  row.appendChild(cancel);
  row.appendChild(msg);
  form.appendChild(row);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    save.disabled = true;
    msg.textContent = "";
    msg.classList.remove("error");
    try {
      await saveShortcut({ id: draft.id || "", name: nameInput.value, command: cmdInput.value });
      scEditing = null;
      await loadShortcuts();
    } catch (err) {
      msg.textContent = err.message || String(err);
      msg.classList.add("error");
      save.disabled = false;
    }
  });

  // Focus the field most likely to be edited: the name for a new shortcut, the
  // command when tweaking an existing one.
  setTimeout(() => (draft.id ? cmdInput : nameInput).focus(), 0);
  return form;
}

// field wraps a labeled input in the form's standard markup.
function field(labelText, input) {
  const wrap = document.createElement("div");
  wrap.className = "field";
  const label = document.createElement("label");
  label.textContent = labelText;
  wrap.appendChild(label);
  wrap.appendChild(input);
  return wrap;
}

async function saveShortcut(payload) {
  const res = await fetch("/api/shortcuts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (res.status === 401) {
    checkAccess();
    throw new Error("Session expired — sign in again.");
  }
  if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
}

async function deleteShortcut(sc) {
  if (!confirm(`Delete shortcut “${sc.name}”?`)) return;
  try {
    const res = await fetch("/api/shortcuts/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: sc.id }),
    });
    if (res.status === 401) return checkAccess();
    if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
    await loadShortcuts();
  } catch (err) {
    showError("Delete failed: " + (err.message || err));
  }
}

// --- auth gate ----------------------------------------------------------

function startRefreshing() {
  if (barEl) barEl.style.display = "";
  if (scSection) scSection.hidden = false;
  if (refreshTimer) return;
  loadShortcuts(); // load once on sign-in; sessions refresh on their own timer
  refresh();
  refreshTimer = setInterval(refresh, REFRESH_MS);
}

function stopRefreshing() {
  clearInterval(refreshTimer);
  refreshTimer = null;
}

// renderGate draws a centered card. When `enroll` is true the visitor has no
// passkey yet and we offer to create one; otherwise we offer to unlock with an
// existing passkey. `label`/null buttons fall back to a static message (used
// for the insecure-context notice).
function renderGate({ title, body, label, action }) {
  stopRefreshing();
  if (barEl) barEl.style.display = "none";
  if (scSection) scSection.hidden = true;
  scEditing = null;
  summaryEl.textContent = "";
  statusEl.textContent = "";
  statusEl.classList.remove("error");
  contentEl.innerHTML = "";

  const card = document.createElement("div");
  card.className = "gate-card";

  const logo = document.createElement("div");
  logo.className = "logo";
  logo.textContent = "▮";
  card.appendChild(logo);

  const h = document.createElement("h2");
  h.textContent = title;
  card.appendChild(h);

  const p = document.createElement("p");
  p.textContent = body;
  card.appendChild(p);

  if (label && action) {
    const btn = document.createElement("button");
    btn.className = "btn-primary";
    btn.type = "button";
    btn.textContent = label;
    const msg = document.createElement("div");
    msg.className = "msg";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      msg.textContent = "";
      msg.classList.remove("error");
      try {
        await action();
        startRefreshing(); // session cookie is set; load the list in place
      } catch (err) {
        msg.textContent = err.message || String(err);
        msg.classList.add("error");
        btn.disabled = false;
      }
    });
    card.appendChild(btn);
    card.appendChild(msg);
  }

  contentEl.appendChild(card);
}

function showGate(enrolled) {
  if (enrolled) {
    renderGate({
      title: "Locked",
      body: "Use your passkey to unlock the session console.",
      label: "Unlock with passkey",
      action: () => Passkey.signIn(),
    });
  } else {
    renderGate({
      title: "Welcome",
      body: "Create a passkey to secure access. You'll use it every time you return.",
      label: "Create passkey",
      action: () => Passkey.enroll(),
    });
  }
}

// checkAccess runs on load and again whenever a request comes back 401 (session
// expired). It either starts the refresh loop or shows the right passkey prompt.
async function checkAccess() {
  stopRefreshing();
  // An insecure context means the CA isn't trusted (or this isn't HTTPS); send
  // the visitor to the setup page to download and trust it.
  if (!window.isSecureContext) {
    location.replace("/cert");
    return;
  }
  if (!window.PublicKeyCredential) {
    renderGate({
      title: "Passkeys unavailable",
      body: "This browser does not support passkeys (WebAuthn), which the console requires.",
    });
    return;
  }
  let status;
  try {
    status = await (await fetch("/api/status")).json();
  } catch (err) {
    renderGate({ title: "Offline", body: "Cannot reach the server." });
    return;
  }
  if (status.authenticated) startRefreshing();
  else showGate(status.enrolled);
}

function showError(msg) {
  statusEl.textContent = msg;
  statusEl.classList.add("error");
}

function badge(state) {
  const b = document.createElement("span");
  b.className = "badge " + (state === "busy" ? "busy" : "idle");
  const dot = document.createElement("span");
  dot.className = "dot";
  b.appendChild(dot);
  b.appendChild(document.createTextNode(state === "busy" ? "busy" : "idle"));
  return b;
}

function renderSessions(sessions) {
  contentEl.innerHTML = "";

  const conns = sessions.reduce((n, s) => n + s.connections, 0);
  summaryEl.textContent =
    sessions.length === 0
      ? "No active sessions."
      : `${sessions.length} session${sessions.length === 1 ? "" : "s"} · ` +
        `${conns} connection${conns === 1 ? "" : "s"}`;

  if (sessions.length === 0) {
    const e = document.createElement("div");
    e.className = "empty";
    e.textContent = "Nothing running yet. Click “New session” to start one.";
    contentEl.appendChild(e);
    return;
  }

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML =
    "<tr><th>Session</th><th>Title</th><th>State</th>" +
    '<th style="text-align:right">Conns</th>' +
    '<th style="text-align:right">Idle</th>' +
    '<th style="text-align:right">Age</th>' +
    '<th style="text-align:right">Actions</th></tr>';
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  for (const s of sessions) {
    const tr = document.createElement("tr");

    const idTd = document.createElement("td");
    idTd.className = "id";
    idTd.textContent = s.id.length > 12 ? s.id.slice(0, 12) + "…" : s.id;
    idTd.title = s.id;
    tr.appendChild(idTd);

    // Window title the shell/program set (OSC 0/2). Empty for shells that never
    // set one; the full title is on the hover tooltip when it's truncated.
    const titleTd = document.createElement("td");
    titleTd.className = "title-cell";
    if (s.title) {
      titleTd.textContent = s.title;
      titleTd.title = s.title;
    } else {
      titleTd.textContent = "—";
      titleTd.classList.add("empty-title");
    }
    tr.appendChild(titleTd);

    const stateTd = document.createElement("td");
    stateTd.appendChild(badge(s.state));
    tr.appendChild(stateTd);

    const connTd = document.createElement("td");
    connTd.className = "num";
    connTd.textContent = String(s.connections);
    tr.appendChild(connTd);

    const idleTd = document.createElement("td");
    idleTd.className = "num";
    idleTd.textContent = formatDuration(s.idleSeconds);
    tr.appendChild(idleTd);

    const ageTd = document.createElement("td");
    ageTd.className = "num";
    ageTd.textContent = formatDuration(s.ageSeconds);
    tr.appendChild(ageTd);

    const actTd = document.createElement("td");
    actTd.className = "actions";

    const join = document.createElement("a");
    join.className = "join";
    join.href = "/?session=" + encodeURIComponent(s.id);
    join.target = "_blank";
    join.rel = "noopener";
    join.textContent = "Join";
    actTd.appendChild(join);

    const kill = document.createElement("button");
    kill.className = "kill";
    kill.type = "button";
    kill.textContent = "Kill";
    kill.disabled = killing.has(s.id);
    kill.addEventListener("click", () => killSession(s.id));
    actTd.appendChild(kill);

    tr.appendChild(actTd);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  contentEl.appendChild(table);
}

async function killSession(id) {
  if (!confirm("Kill this session? Its shell and any running command will be terminated.")) return;
  killing.add(id);
  refresh(); // reflect the disabled button immediately
  try {
    const res = await fetch("/api/sessions/kill", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    if (res.status === 401) return checkAccess();
    if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
  } catch (err) {
    showError("Kill failed: " + (err.message || err));
  } finally {
    killing.delete(id);
    refresh();
  }
}

async function refresh() {
  if (fetching) return;
  fetching = true;
  try {
    const res = await fetch("/api/sessions", { headers: { Accept: "application/json" } });
    if (res.status === 401) return checkAccess();
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    statusEl.classList.remove("error");
    statusEl.textContent = "auto-refreshing";
    renderSessions(data.sessions || []);
  } catch (err) {
    showError("Cannot reach the server.");
  } finally {
    fetching = false;
  }
}

checkAccess();
