"use strict";

// Passkey (WebAuthn) enrollment and sign-in live in the shared passkey.js,
// loaded before this script and exposed as window.Passkey.

// Standard base64 of arbitrary bytes, chunked to avoid call-stack limits on
// large images.
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

// --- clickable links ----------------------------------------------------

// URLs are detected anywhere in the screen and opened with a Cmd/Ctrl-click
// (matching the convention in VS Code's and iTerm's terminals). A plain click
// is left alone so it never interferes with selecting text inside a URL.

// Match http(s) URLs. Cells that are blank render as spaces (see buildLogical),
// so [^\s] naturally stops a match at the first gap.
const URL_RE = /https?:\/\/[^\s]+/gi;

// trimUrl drops trailing punctuation that is almost certainly sentence noise
// rather than part of the link (e.g. the period in "see http://x.com."). A
// closing bracket is kept when its opener appears inside the URL, so links like
// .../Foo_(bar) survive.
function trimUrl(s) {
  while (s.length) {
    const ch = s[s.length - 1];
    if (")]}".includes(ch)) {
      const open = { ")": "(", "]": "[", "}": "{" }[ch];
      if (s.includes(open)) break;
    } else if (!".,;:!?'\"<>".includes(ch)) {
      break;
    }
    s = s.slice(0, -1);
  }
  return s;
}

// buildLogical reconstructs the full (possibly soft-wrapped) line that passes
// through buffer row `idx`, walking up while rows are continuations and down
// while the next row is one. It returns the joined text plus a parallel cellMap
// giving the buffer {row, col} that produced each character, so a regex match
// index can be turned back into screen coordinates. Walking cells (rather than
// translateToString) keeps the mapping correct across wide (CJK) glyphs.
function buildLogical(term, idx) {
  const buffer = term.buffer.active;
  const cols = term.cols;

  let top = idx;
  while (top > 0 && buffer.getLine(top) && buffer.getLine(top).isWrapped) top--;
  let bottom = idx;
  while (
    bottom < buffer.length - 1 &&
    buffer.getLine(bottom + 1) &&
    buffer.getLine(bottom + 1).isWrapped
  ) {
    bottom++;
  }

  let text = "";
  const cellMap = [];
  const cell = buffer.getNullCell ? buffer.getNullCell() : undefined;
  for (let row = top; row <= bottom; row++) {
    const line = buffer.getLine(row);
    if (!line) continue;
    for (let col = 0; col < cols; col++) {
      const c = line.getCell(col, cell);
      if (!c) continue;
      if (c.getWidth() === 0) continue; // right half of a wide glyph
      let ch = c.getChars();
      if (ch === "") ch = " "; // an empty cell reads as a space
      for (let k = 0; k < ch.length; k++) cellMap.push({ row, col });
      text += ch;
    }
  }
  return { text, cellMap };
}

// setupTerminalLinks wires URL detection into the terminal. A hovered URL is
// underlined (with a pointer cursor) so it is discoverable; opening it still
// requires a Cmd/Ctrl-click, which launches it in a new tab with the opener
// relationship severed for safety.
function setupTerminalLinks(term) {
  term.registerLinkProvider({
    provideLinks(bufferLineNumber, callback) {
      const idx = bufferLineNumber - 1; // provider rows are 1-based
      if (idx < 0 || idx >= term.buffer.active.length) return callback(undefined);

      const { text, cellMap } = buildLogical(term, idx);
      const links = [];
      URL_RE.lastIndex = 0;
      let m;
      while ((m = URL_RE.exec(text)) !== null) {
        const url = trimUrl(m[0]);
        if (!url) continue;
        const start = cellMap[m.index];
        const end = cellMap[m.index + url.length - 1];
        if (!start || !end) continue;
        links.push({
          text: url,
          range: {
            start: { x: start.col + 1, y: start.row + 1 }, // ranges are 1-based
            end: { x: end.col + 1, y: end.row + 1 },
          },
          // Underline + pointer cursor while hovered so URLs are discoverable;
          // opening still requires the Cmd/Ctrl-click handled in activate.
          decorations: { pointerCursor: true, underline: true },
          activate: (event, uri) => {
            if (event.metaKey || event.ctrlKey) {
              window.open(uri, "_blank", "noopener,noreferrer");
            }
          },
        });
      }
      callback(links.length ? links : undefined);
    },
  });
}

// --- UI -----------------------------------------------------------------

const overlay = document.getElementById("overlay");
const titleEl = document.getElementById("title");
const subtitleEl = document.getElementById("subtitle");
const actionBtn = document.getElementById("action");
const messageEl = document.getElementById("message");

function showMessage(text, isError) {
  messageEl.textContent = text || "";
  messageEl.classList.toggle("error", !!isError);
}

function setPrompt(title, subtitle, label, handler) {
  titleEl.textContent = title;
  subtitleEl.textContent = subtitle;
  actionBtn.textContent = label;
  actionBtn.style.display = "block";
  actionBtn.disabled = false;
  actionBtn.onclick = async () => {
    actionBtn.disabled = true;
    showMessage("");
    try {
      await handler();
    } catch (err) {
      showMessage(err.message || String(err), true);
      actionBtn.disabled = false;
    }
  };
}

// --- passkey flows ------------------------------------------------------
// Thin wrappers over the shared flows: authenticate, then drop into the shell.

async function enroll() {
  await Passkey.enroll();
  startTerminal();
}

async function signIn() {
  await Passkey.signIn();
  startTerminal();
}

// --- terminal -----------------------------------------------------------

function startTerminal() {
  overlay.classList.add("hidden");

  const term = new Terminal({
    cursorBlink: true,
    fontFamily: "ui-monospace, Menlo, Consolas, monospace",
    fontSize: 14,
    theme: { background: "#0b0e14", foreground: "#cdd6f4", cursor: "#cdd6f4" },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById("terminal"));
  fit.fit();
  term.focus();

  // Reflect the shell/program's window title (OSC 0/2) in the browser tab, so a
  // tab running a long job — or sitting in a particular directory — is
  // identifiable at a glance among a row of open terminals.
  term.onTitleChange((t) => {
    document.title = t ? t + " — WebSSH" : "WebSSH";
  });

  // Cmd/Ctrl-click a URL in the output to open it in a new tab.
  setupTerminalLinks(term);

  // Drag-to-scroll on touch devices (see setupTouchScroll).
  setupTouchScroll();

  // The session ID lives in the URL (?session=…). The server keeps the shell
  // alive independently of this socket, so reloading or reconnecting re-attaches
  // to the same session and replays its screen.
  const sessionId = new URLSearchParams(location.search).get("session") || "";
  // When the console launches a tab to run a shortcut, it adds ?run=<shortcutId>.
  // We resolve the stored command and type it at the prompt once connected.
  const runShortcutId = new URLSearchParams(location.search).get("run") || "";
  let ranShortcut = false; // guard so a reconnect does not re-run the command
  const encoder = new TextEncoder();
  let ws = null;
  let sessionEnded = false;
  let reconnectAttempts = 0;
  let reconnectTimer = null;

  const sendResize = () => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
    }
  };

  // Live round-trip latency: every couple of seconds we send a timestamped
  // ping; the server echoes it back as a pong (see ServeWS), and the gap is the
  // real end-to-end RTT — network plus TLS/websocket plus the server's read and
  // write path, which a raw ICMP ping never captures. It is shown as a small,
  // smoothed readout in the corner, colored green/amber/red by severity.
  const latencyEl = document.getElementById("latency");
  let rttEma = null;
  let pingTimer = null;

  function updateLatency(t) {
    const rtt = Date.now() - Number(t);
    if (!isFinite(rtt) || rtt < 0) return;
    rttEma = rttEma === null ? rtt : rttEma * 0.7 + rtt * 0.3;
    const ms = Math.round(rttEma);
    latencyEl.textContent = ms + " ms";
    latencyEl.style.color = ms >= 120 ? "#f38ba8" : ms >= 50 ? "#f9e2af" : "#a6e3a1";
    latencyEl.classList.add("show");
    latencyEl.classList.remove("stale");
  }

  function startPing() {
    stopPing();
    const ping = () => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "ping", t: Date.now() }));
      }
    };
    ping();
    pingTimer = setInterval(ping, 2000);
  }

  function stopPing() {
    clearInterval(pingTimer);
    pingTimer = null;
    latencyEl.classList.add("stale"); // dim the last reading while disconnected
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const qs = sessionId ? `?session=${encodeURIComponent(sessionId)}` : "";
    ws = new WebSocket(`${proto}://${location.host}/ws${qs}`);
    ws.binaryType = "arraybuffer";

    ws.onopen = () => {
      if (reconnectAttempts > 0) termWrite("\r\n\x1b[32m[reconnected]\x1b[0m\r\n");
      reconnectAttempts = 0;
      sendResize();
      startPing();
      term.focus();
      maybeRunShortcut();
    };
    ws.onmessage = (e) => {
      if (typeof e.data === "string") {
        try {
          const m = JSON.parse(e.data);
          if (m.type === "exit") sessionEnded = true;
          else if (m.type === "error") termWrite(`\r\n\x1b[31m[${m.message || "error"}]\x1b[0m\r\n`);
          else if (m.type === "pong") updateLatency(m.t);
        } catch (_) {}
        return;
      }
      termWrite(new Uint8Array(e.data));
    };
    ws.onclose = () => {
      stopPing();
      if (sessionEnded) {
        // The shell exited — try to close this tab. Browsers only honor
        // window.close() for tabs a script opened (the console's "New session"
        // button and Join links qualify); a manually opened tab stays put, so
        // fall back to a message once it's clear the close was ignored.
        window.close();
        setTimeout(() => {
          flushWrites(); // surface any held output, then the final notice (direct: session is over)
          term.write("\r\n\x1b[31m[session ended — reload for a new shell]\x1b[0m\r\n");
        }, 300);
        return;
      }
      reconnectAttempts++;
      if (reconnectAttempts > 30) {
        termWrite("\r\n\x1b[31m[disconnected]\x1b[0m\r\n");
        return;
      }
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(connect, Math.min(3000, 400 * reconnectAttempts));
    };
    ws.onerror = () => {};
  }

  // Keystrokes go out as binary frames; control messages as text frames.
  const rawSend = (d) => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(d));
  };

  // clearRunParam drops ?run=<id> from the address bar once we've committed to
  // running the shortcut, so a full page reload re-attaches to the same shell
  // (via ?session=) without re-typing the command. The in-memory ranShortcut
  // guard only survives reconnects, not reloads — the URL has to forget it too.
  function clearRunParam() {
    const url = new URL(location.href);
    if (!url.searchParams.has("run")) return;
    url.searchParams.delete("run");
    history.replaceState(null, "", url.pathname + url.search + url.hash);
  }

  // maybeRunShortcut, on the first successful connect of a ?run=<id> tab, fetches
  // that stored shortcut and types its command at the prompt. The fetch round
  // trip also gives the freshly spawned shell a moment to print its prompt first.
  async function maybeRunShortcut() {
    if (!runShortcutId || ranShortcut) return;
    ranShortcut = true; // set before awaiting so a reconnect can't double-fire
    clearRunParam();    // ...and forget it in the URL so a reload won't re-run it
    try {
      const res = await fetch("/api/shortcuts", { headers: { Accept: "application/json" } });
      if (!res.ok) return;
      const data = await res.json();
      const sc = (data.shortcuts || []).find((s) => s.id === runShortcutId);
      if (!sc || !sc.command) return;
      // Send carriage returns (what Enter produces) so the command executes; a
      // multi-line shortcut runs line by line, with a final Enter on the last.
      const cmd = sc.command.replace(/\r?\n/g, "\r").replace(/\r$/, "") + "\r";
      rawSend(cmd);
    } catch (_) {}
  }

  // Sticky modifiers armed from the on-screen key bar. They apply to the next
  // keystroke, then clear. Ctrl maps a key to its control code; Opt (Alt) sends
  // an ESC prefix.
  const mods = { ctrl: false, alt: false };

  function ctrlByte(s) {
    if (s.length !== 1) return null;
    const code = s.toLowerCase().charCodeAt(0);
    if (code >= 97 && code <= 122) return String.fromCharCode(code - 96); // a-z -> 0x01..0x1a
    const map = { " ": "\x00", "@": "\x00", "[": "\x1b", "\\": "\x1c", "]": "\x1d", "^": "\x1e", "_": "\x1f", "?": "\x7f" };
    return map[s] != null ? map[s] : null;
  }

  // sendInput applies any armed modifiers to typed data, then transmits it.
  function sendInput(d) {
    if (mods.ctrl || mods.alt) {
      let out = d;
      if (mods.ctrl) {
        const b = ctrlByte(d);
        if (b != null) out = b;
      }
      if (mods.alt) out = "\x1b" + out;
      clearMods();
      rawSend(out);
      return;
    }
    rawSend(d);
  }

  let clearMods = () => {}; // replaced by setupKeyBar when the bar is present

  term.onData(sendInput);
  term.onResize(sendResize);
  window.addEventListener("resize", () => fit.fit());

  // Send an image file's original bytes over the websocket; the server saves it
  // and types the path at the prompt. Bytes are passed through untouched, so
  // there is no re-encoding or downscaling on our side.
  async function sendImageFile(file) {
    try {
      const buf = await file.arrayBuffer();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(
          JSON.stringify({ type: "image", mime: file.type || "image/png", data: bufToB64(buf) })
        );
      }
    } catch (err) {
      termWrite("\r\n\x1b[31m[image upload failed]\x1b[0m\r\n");
    }
  }

  const termEl = document.getElementById("terminal");

  // --- selection-friendly output ----------------------------------------
  //
  // This xterm build uses the DOM renderer, whose "selection" is the browser's
  // native selection anchored to the row elements. Any repaint of the rows under
  // a selection destroys those nodes, so the browser collapses the selection and
  // xterm clears it — which is why a highlight won't "stick" while output flows
  // (a redrawing prompt, a tmux/powerline status line, a TUI, streaming output).
  // The latency readout is unrelated: it's a separate fixed, pointer-events:none
  // badge, and updating its text never touches the terminal rows.
  //
  // Two guards make highlight-to-copy reliable:
  //  1. While text is selected, hold incoming output and flush it in order once
  //     the selection clears, so nothing repaints out from under the highlight.
  //  2. Copy the selection to the clipboard the instant a drag finishes, so the
  //     text is captured even if some later repaint does collapse the highlight.
  let writeQueue = [];
  let queuedBytes = 0;
  const MAX_QUEUED_BYTES = 4 * 1024 * 1024; // output integrity wins over a held selection

  function flushWrites() {
    if (!writeQueue.length) return;
    const q = writeQueue;
    writeQueue = [];
    queuedBytes = 0;
    for (const d of q) term.write(d);
  }

  // termWrite is the single sink for everything we paint: it defers to the queue
  // while a selection is held, except past a hard byte cap, where keeping output
  // flowing matters more than preserving one selection during a flood.
  function termWrite(data) {
    if (term.hasSelection()) {
      writeQueue.push(data);
      queuedBytes += data.length || 0;
      if (queuedBytes > MAX_QUEUED_BYTES) {
        term.clearSelection(); // fires onSelectionChange below, which also flushes
        flushWrites();
      }
      return;
    }
    term.write(data);
  }

  // The moment a selection clears (deselect, a keystroke, or a programmatic
  // clear), release everything we held back.
  term.onSelectionChange(() => {
    if (!term.hasSelection()) flushWrites();
  });

  // Copy-on-select: grab the highlight as soon as the drag ends. mouseup is a
  // user gesture, so the clipboard write is allowed in this secure context; we
  // listen on the document so a drag that ends outside the terminal still copies.
  document.addEventListener("mouseup", () => {
    if (!term.hasSelection()) return;
    const sel = term.getSelection();
    if (sel && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(sel).catch(() => {});
    }
  });

  // Pasting an image (e.g. a screenshot). Text pastes are left to xterm. When
  // the clipboard offers several formats, prefer lossless PNG.
  termEl.addEventListener(
    "paste",
    (e) => {
      const items = (e.clipboardData && e.clipboardData.items) || [];
      let chosen = null;
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        if (it.kind === "file" && it.type && it.type.startsWith("image/")) {
          if (!chosen || it.type === "image/png") chosen = it;
        }
      }
      if (chosen) {
        e.preventDefault();
        e.stopPropagation();
        const file = chosen.getAsFile();
        if (file) sendImageFile(file);
      }
    },
    true
  );

  // Dragging an image file in gives the original, full-resolution bytes — the
  // best quality, since it skips the screenshot/clipboard round-trip.
  termEl.addEventListener("dragover", (e) => e.preventDefault());
  termEl.addEventListener("drop", (e) => {
    const files = (e.dataTransfer && e.dataTransfer.files) || [];
    let handled = false;
    for (let i = 0; i < files.length; i++) {
      if (files[i].type && files[i].type.startsWith("image/")) {
        sendImageFile(files[i]);
        handled = true;
      }
    }
    if (handled) {
      e.preventDefault();
      e.stopPropagation();
    }
  });

  setupKeyBar();

  // setupTouchScroll turns a finger drag over the terminal into scrolling. It
  // translates the drag into "wheel" events and dispatches them to xterm's
  // screen element, which already knows what to do with a wheel: scroll its own
  // scrollback at a plain prompt, or — when the foreground app has mouse
  // tracking on, as tmux (mouse on), htop, less and vim do — encode them as the
  // mouse-wheel input that app expects. One gesture, correct everywhere, with no
  // guessing about the negotiated mouse protocol. A plain tap is left untouched
  // so it still focuses the terminal (and reaches the app as a click in tmux).
  function setupTouchScroll() {
    const el = document.getElementById("terminal");
    let lastY = null; // clientY of the active drag, or null when not dragging
    let accum = 0; // pixels dragged but not yet spent on a whole row

    // Pixel height of one row, used as one wheel "notch" so a notch ≈ one line.
    const rowPx = () => {
      const vp = el.querySelector(".xterm-viewport");
      const rows = term.rows || 24;
      return vp && vp.clientHeight ? vp.clientHeight / rows : 18;
    };

    const wheel = (deltaY, x, y) => {
      const screen = el.querySelector(".xterm-screen") || el.querySelector(".xterm");
      if (!screen) return;
      screen.dispatchEvent(
        new WheelEvent("wheel", {
          deltaY, // >0 scrolls toward newer output, <0 toward history
          deltaMode: 0, // pixels
          clientX: x,
          clientY: y,
          bubbles: true,
          cancelable: true,
        })
      );
    };

    el.addEventListener(
      "touchstart",
      (e) => {
        if (e.touches.length !== 1) {
          lastY = null; // ignore multi-touch (pinch); let the browser have it
          return;
        }
        lastY = e.touches[0].clientY;
        accum = 0;
      },
      { passive: true }
    );

    el.addEventListener(
      "touchmove",
      (e) => {
        if (lastY === null) return;
        if (e.touches.length !== 1) {
          lastY = null;
          return;
        }
        const t = e.touches[0];
        accum += lastY - t.clientY; // finger up => positive => scroll to newer
        lastY = t.clientY;
        const step = rowPx();
        let rows = Math.trunc(accum / step);
        if (rows !== 0) {
          accum -= rows * step;
          // One discrete wheel event per row so mouse-mode apps (tmux copy-mode,
          // less) advance a line each, rather than collapsing to a single notch.
          const dir = rows > 0 ? step : -step;
          const n = Math.min(Math.abs(rows), 24); // cap a single frame's burst
          for (let i = 0; i < n; i++) wheel(dir, t.clientX, t.clientY);
        }
        // We own this gesture: keep the page from panning and stop xterm's own
        // touch handler from scrolling a second time.
        e.preventDefault();
        e.stopPropagation();
      },
      { passive: false, capture: true }
    );

    const release = () => {
      lastY = null;
    };
    el.addEventListener("touchend", release, { passive: true });
    el.addEventListener("touchcancel", release, { passive: true });
  }

  // setupKeyBar shows an on-screen modifier/key bar on touch devices (phones,
  // tablets) and keeps it docked above the soft keyboard.
  function setupKeyBar() {
    const touch =
      navigator.maxTouchPoints > 0 &&
      (/iPhone|iPad|iPod|Android|Mobile/i.test(navigator.userAgent) ||
        (window.matchMedia && window.matchMedia("(pointer: coarse)").matches));
    if (!touch) return;

    const bar = document.getElementById("keybar");
    bar.classList.add("show");

    const modBtns = { ctrl: "mod-ctrl", alt: "mod-alt" };
    function setMod(name, on) {
      mods[name] = on;
      document.getElementById(modBtns[name]).classList.toggle("active", on);
    }
    clearMods = () => {
      setMod("ctrl", false);
      setMod("alt", false);
    };

    // Use pointerdown + preventDefault so tapping a button never steals focus
    // from the terminal, keeping the soft keyboard open.
    function onTap(id, fn) {
      document.getElementById(id).addEventListener("pointerdown", (e) => {
        e.preventDefault();
        fn();
        term.focus();
      });
    }

    // onHold gives one button two actions — a quick tap and a press-and-hold —
    // so a single key can serve double duty and keep the bar compact. Like
    // onTap it preventDefaults to avoid stealing focus from the terminal.
    function onHold(id, tapFn, holdFn, ms) {
      const btn = document.getElementById(id);
      let timer = null;
      let held = false;
      btn.addEventListener("pointerdown", (e) => {
        e.preventDefault();
        held = false;
        btn.classList.add("active");
        timer = setTimeout(() => {
          held = true; // crossed the hold threshold: fire the hold action once
          holdFn();
        }, ms || 350);
      });
      const finish = (runTap) => (e) => {
        e.preventDefault();
        clearTimeout(timer);
        timer = null;
        btn.classList.remove("active");
        if (runTap && !held) tapFn();
        term.focus();
      };
      btn.addEventListener("pointerup", finish(true));
      // A pointer that slides off or is cancelled neither taps nor re-fires.
      btn.addEventListener("pointerleave", finish(false));
      btn.addEventListener("pointercancel", finish(false));
    }

    onTap("key-esc", () => {
      clearMods();
      rawSend("\x1b");
    });
    // Tab on a quick tap (used constantly), Shift+Tab on a hold — folding the
    // back-tab into a hold keeps the bar to four keys.
    onHold(
      "key-tab",
      () => {
        clearMods();
        rawSend("\t");
      },
      () => {
        clearMods();
        rawSend("\x1b[Z"); // CSI Z = back-tab (Shift+Tab)
      }
    );
    onTap("mod-ctrl", () => setMod("ctrl", !mods.ctrl));
    onTap("mod-alt", () => setMod("alt", !mods.alt));

    // Keep the bar just above the on-screen keyboard and the terminal above the
    // bar, using the visual viewport to detect the keyboard height.
    function layout() {
      let kb = 0;
      const vv = window.visualViewport;
      if (vv) kb = Math.max(0, window.innerHeight - vv.height - vv.offsetTop);
      bar.style.bottom = kb + "px";
      termEl.style.bottom = kb + bar.offsetHeight + "px";
      fit.fit();
    }
    if (window.visualViewport) {
      window.visualViewport.addEventListener("resize", layout);
      window.visualViewport.addEventListener("scroll", layout);
    }
    window.addEventListener("resize", layout);
    layout();
  }

  // Open the websocket last, once all handlers are wired up.
  connect();
}

// --- boot ---------------------------------------------------------------

async function boot() {
  // An insecure context means the browser does not trust the server's
  // certificate (or this isn't HTTPS). Send the visitor straight to the setup
  // page to download and trust the CA — which is also what passkeys require.
  if (!window.isSecureContext) {
    location.replace("/cert");
    return;
  }
  if (!window.PublicKeyCredential) {
    titleEl.textContent = "Passkeys unavailable";
    subtitleEl.textContent =
      "This browser does not support passkeys (WebAuthn), which this terminal requires.";
    return;
  }
  let status;
  try {
    status = await (await fetch("/api/status")).json();
  } catch (err) {
    subtitleEl.textContent = "Cannot reach the server.";
    return;
  }
  if (status.authenticated) {
    startTerminal();
  } else if (status.enrolled) {
    setPrompt("Locked", "Use your passkey to unlock this terminal.", "Unlock with passkey", signIn);
  } else {
    setPrompt(
      "Welcome",
      "Create a passkey to secure access. You'll use it every time you return.",
      "Create passkey",
      enroll
    );
  }
}

boot();
