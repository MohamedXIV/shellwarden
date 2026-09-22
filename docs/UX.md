# UX Contract

## Product character

ShellWarden should feel like a focused native developer control center: compact, calm, dark-mode friendly, information-dense without becoming a generic SaaS dashboard.

It is not a terminal emulator.

## Main navigation

v0.1 has five primary surfaces:

1. **Dashboard** — connection state, active executions, pending approvals, recent decisions.
2. **Activity** — structured real-time execution blocks and bounded output.
3. **Approvals** — requests that need user attention.
4. **Permissions** — inspect, search, revoke, and reset grants.
5. **Audit** — durable decision/execution history.

Settings remains secondary.

## Header

Always show:

- remote access: on / paused / disconnected;
- MCP/broker health;
- tunnel status when enabled;
- prominent **Pause Remote Access** action.

Connection state must never be hidden only in settings.

## Activity blocks

Each execution block should show, where known:

- requester/client;
- executable or recognizable tool;
- command summary;
- working directory/repository;
- status;
- elapsed time;
- risk class;
- bounded live stdout/stderr;
- final result.

Prefer collapsible structured blocks over one global terminal scroll.

## Approval card

An approval must explain:

- what wants to run;
- where;
- why it is considered risky or unknown;
- what the chosen scope means.

Typical choices:

```text
Allow once
Allow for this session
Allow in this directory/repository
Allow in this directory tree
Always allow       (only when permitted)
Deny
```

Critical operations use stronger copy and may expose fewer persistence choices.

## Tray

Closing the window may minimize to tray.

Tray menu should provide at minimum:

```text
Open ShellWarden
----------------
Remote access: ON / PAUSED
N tasks running
M approvals waiting
----------------
Pause/Resume Remote Access
----------------
Exit
```

Pending approvals should be visible through tray state/notification.

## Exit

Exit is not minimize.

If managed work is running, ShellWarden asks whether to stop tasks and exit or cancel the exit.

After confirmed Exit, no ShellWarden remote endpoint/tunnel/service intentionally remains running.

## First-run experience

Keep v0.1 onboarding short:

1. explain that ShellWarden is not an OS sandbox;
2. recommend a dedicated standard OS user;
3. choose/confirm workspace roots;
4. configure remote transport;
5. start with conservative policy defaults.

Do not bury the security model behind a long wizard.
