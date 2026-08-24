<script lang="ts">
  // §31.1: "xterm.js-class emulator wired to `terminal://output` /
  // `submit_command`... real terminal feel (cursor, ANSI color for risk
  // levels, scrollback) without reimplementing a renderer." This
  // component is deliberately dumb: it owns keystrokes and rendering
  // only. It has no IPC calls and no knowledge of policy/risk/category —
  // it dispatches `submit`/`interrupt` events and exposes `writeOutput`/
  // `writeSystemLine` for the parent (`App.svelte`, the actual event-
  // stream subscriber) to call. That split is what keeps this a "pure
  // renderer" (docs/CLAUDE.md) rather than a second place decisions get
  // made.
  import { createEventDispatcher, onDestroy, onMount } from "svelte";
  import { Terminal as XTerm } from "@xterm/xterm";
  import "@xterm/xterm/css/xterm.css";

  export let prompt = "aegis> ";

  let container: HTMLDivElement;
  let term: XTerm;
  let buffer = "";

  const dispatch = createEventDispatcher<{ submit: string; interrupt: void }>();

  // 256-color codes chosen to match the app's pastel-terracotta accent
  // (173) and muted danger (174) tokens (`App.svelte`'s `--accent`/
  // `--danger`) — xterm's theme is a plain JS object evaluated once, not
  // living CSS, so it can't reference the CSS custom properties directly;
  // these are that palette's nearest ANSI-256 equivalents.
  const PROMPT_COLOR = "38;5;173";
  const ERROR_COLOR = "38;5;174";

  function writePrompt() {
    term.write(`\r\n\x1b[${PROMPT_COLOR}m${prompt}\x1b[0m`);
  }

  /** A one-line system message (parse errors, deny/unsupported echoes) —
   * `colorCode` is a raw ANSI SGR code, e.g. "38;5;174" for the muted
   * danger tone, "38;5;173" for a neutral/notice tone. */
  export function writeSystemLine(text: string, colorCode = "0") {
    term.write(`\r\n\x1b[${colorCode}m${text}\x1b[0m`);
    writePrompt();
  }

  /** Real command output, once `executor::execute` has actually run —
   * never simulation output (see `orchestrator::TerminalOutputEvent`'s
   * doc comment for why the terminal must never display a prediction as
   * if it were real). */
  export function writeOutput(stdout: string, stderr: string) {
    if (stdout) term.write(`\r\n${stdout.replace(/\n/g, "\r\n")}`);
    if (stderr) term.write(`\r\n\x1b[${ERROR_COLOR}m${stderr.replace(/\n/g, "\r\n")}\x1b[0m`);
    writePrompt();
  }

  onMount(() => {
    term = new XTerm({
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      fontSize: 14,
      theme: {
        background: "#0a0a0b",
        foreground: "#e7e5e1",
        cursor: "#d99a6c",
        cursorAccent: "#0a0a0b",
        selectionBackground: "rgba(217, 154, 108, 0.18)",
      },
    });
    term.open(container);
    term.write("Aegis — simulate → understand → approve → execute → verify → recover.");
    writePrompt();
    term.focus();

    term.onData((data) => {
      const code = data.charCodeAt(0);
      if (data === "\r") {
        const line = buffer;
        buffer = "";
        if (line.trim().length === 0) {
          writePrompt();
          return;
        }
        term.write("\r\n");
        dispatch("submit", line);
      } else if (code === 127 || code === 8) {
        if (buffer.length > 0) {
          buffer = buffer.slice(0, -1);
          term.write("\b \b");
        }
      } else if (code === 3) {
        buffer = "";
        term.write("^C");
        dispatch("interrupt");
        writePrompt();
      } else if (code >= 32) {
        buffer += data;
        term.write(data);
      }
    });
  });

  onDestroy(() => {
    term?.dispose();
  });
</script>

<div class="terminal" bind:this={container}></div>

<style>
  .terminal {
    height: 100%;
    width: 100%;
    padding: 0.75rem 1rem;
    box-sizing: border-box;
  }

  .terminal :global(.xterm) {
    height: 100%;
  }
</style>
