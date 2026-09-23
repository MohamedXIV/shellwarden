# Secure MCP Tunnel dogfood

This runbook verifies the real remote boundary for ShellWarden without exposing its local MCP listener to the LAN or public internet.

## What this proves

A successful pass demonstrates:

1. ShellWarden starts its MCP endpoint on an ephemeral \`127.0.0.1\` port.
2. ShellWarden launches and supervises \`tunnel-client\`.
3. The tunnel reaches Ready/Connected state.
4. A supported OpenAI client can discover and call ShellWarden's \`shell_execute\` tool.
5. Unknown authority becomes a ShellWarden approval instead of executing directly.
6. Pause closes the remote gate, cancels pending remote approvals, and terminates the managed tunnel process.
7. Resume launches a fresh managed tunnel process and restores connectivity.
8. Exit terminates tunnel/MCP/broker descendants and leaves no ShellWarden-managed background service.

## Preconditions

- Windows 10/11.
- A current \`tunnel-client\` binary from OpenAI's Platform tunnel settings or the latest public \`openai/tunnel-client\` release.
- A tunnel ID such as \`tunnel_0123456789abcdef0123456789abcdef\`.
- A runtime API key with **Tunnels Read + Use**. Do not use an admin key for the runtime.
- The tunnel must be associated with the OpenAI organization/workspace that will call it.
- Outbound HTTPS access to \`api.openai.com:443\` (or the configured mTLS endpoint).
- For ChatGPT testing, a ChatGPT workspace/account where developer-mode custom MCP apps are currently supported.

ShellWarden does not persist the runtime API key. It exists in UI/Rust process memory and the managed child environment for the current app lifetime.

## 1. Start ShellWarden

From the repository:

\`\`\`powershell
npm install
python -m pip install -r execution/requirements.txt
npm run tauri:dev
\`\`\`

Open **Settings**.

The **ShellWarden MCP** card should show a loopback URL similar to:

\`\`\`text
http://127.0.0.1:<ephemeral-port>/mcp
\`\`\`

Do not expose this listener or replace \`127.0.0.1\` with a LAN address.

## 2. Configure the tunnel from ShellWarden

In **Settings → Secure MCP Tunnel**:

- enter the tunnel ID;
- enter the restricted runtime API key;
- leave the binary as \`tunnel-client\` when it is on PATH, or choose its explicit executable path;
- click **Connect tunnel**.

Expected state:

\`\`\`text
Not configured -> Connecting -> Connected
\`\`\`

When the tunnel publishes its local health address, ShellWarden also shows the local \`/ui\` URL. The health/admin listener must remain loopback-only.

If startup fails, ShellWarden should remain in **Error** and surface the launch/readiness problem instead of silently reverting to disconnected.

## 3. Confirm tunnel readiness

ShellWarden considers the tunnel Connected only after the managed client's \`/readyz\` returns HTTP 200.

Optional operator check: open the health URL shown by ShellWarden with \`/ui\`. It should report the runtime as healthy/ready and polling.

## 4. Connect a supported OpenAI client

### ChatGPT

When custom MCP apps and developer mode are enabled for the target ChatGPT account/workspace:

1. Open ChatGPT's app/plugin creation surface.
2. Create a developer-mode app.
3. Choose **Tunnel** as the connection.
4. Select the associated tunnel or paste its tunnel ID.
5. Scan/discover tools.
6. Confirm that \`shell_execute\` is visible.

If the tunnel does not appear, check workspace association and **Tunnels Read + Use** before debugging ShellWarden.

### Transport-only fallback

If the current ChatGPT plan/workspace cannot create a tunnel-backed custom MCP app, verify the same tunnel with another supported OpenAI surface such as Codex or the Responses API. This proves the transport/runtime integration but does **not** by itself satisfy the ChatGPT-specific acceptance item in Issue #12.

## 5. Harmless request + approval

Request a harmless Git read operation in a real repository, for example an argv request equivalent to:

\`\`\`json
{
  "command": ["git", "status", "--short"],
  "directory": "C:\\path\\to\\repo",
  "timeout_seconds": 30
}
\`\`\`

Expected ShellWarden behavior:

- Activity immediately shows a remote request.
- With no matching grant, the execution enters **Awaiting approval**.
- Approvals shows the exact argv, cwd, risk, and allowed scopes.
- Approving a permitted scope queues and executes the request through the pinned execution core.
- Activity shows the terminal result.
- Audit records why the request was allowed without persisting raw argv/output.

## 6. Pause race/authority test

Start another previously ungranted remote request and leave its approval pending.

Click **Pause Remote Access**.

Expected:

- UI/tray state becomes **Paused**.
- the pending remote approval becomes **Cancelled**;
- the managed \`tunnel-client\` process is terminated;
- a new remote request cannot begin execution;
- directly reaching the loopback MCP endpoint does not restore remote authority while the state is Paused.

## 7. Resume

Click **Resume Remote Access**.

Expected:

- ShellWarden starts a new managed \`tunnel-client\` process;
- state transitions through **Connecting** to **Connected**;
- a new remote request can again reach policy/approval.

The runtime key is retained only in memory for the current ShellWarden lifetime so Resume does not require re-entering it.

## 8. Exit

Use **Exit ShellWarden** from the tray.

Verify that:

- the ShellWarden window/process exits;
- the managed \`tunnel-client\` process is gone;
- the execution broker and managed child processes are gone;
- no ShellWarden Windows Service or hidden always-on helper exists.

## Evidence to record for Issue #12

Record:

- exact ShellWarden branch/SHA;
- \`tunnel-client\` version;
- Connected screenshot or status;
- successful tool discovery;
- one harmless approved Git request and result;
- Pause rejection/cancellation result;
- Resume result;
- tray Connected/Paused state;
- process check after Exit.

Do not paste runtime API keys, raw authorization headers, or secret-bearing environment values into the issue.
