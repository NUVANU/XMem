# XMem

**Carry the project forward, not just the conversation.**

Local, versioned engineering memory with sources, applicability, and explicit retrieval.

**English** · [简体中文](README.zh-CN.md)

[Quick start](#quick-start) · [Engineering API](src/engineering-memory.ts) · [MCP contract](src/engineering-mcp-contract.ts) · [X Suite](https://github.com/NUVANU/X-Suite)

Long development work rarely fits into one chat. After a new session or an agent handoff, the difficult part is often recovering the project’s reasoning: which rule is current, why an interface changed, and which attempted fix already failed.

**XMem stores that history as inspectable project knowledge.** Retrieve relevant records, follow their source references, and check their revision and applicability before using them in the next task.

## What is worth remembering?

| Project knowledge | Why keep it? |
| --- | --- |
| Constraints and decisions | Preserve the reason behind a rule, not only its latest wording |
| Interfaces and module conventions | Give later changes the context they need |
| Failures and attempted fixes | Retain observed symptoms and distinguish supported findings from hypotheses |
| Open questions and unknowns | Keep uncertainty visible across handoffs |
| Task checkpoints | Provide a concrete place to resume and reconcile |

Useful for maintained repositories, long AI-assisted coding tasks, and multi-agent work where repeating the same background is becoming costly.

## A small example

Imagine a tool-booking app with this confirmed rule:

> “Borrowers may cancel their own reservations before the start time.”

A later session should be able to find the rule, its source, and the task/version it applied to. If the rule changes, an older revision should remain inspectable without silently becoming the current answer.

Likewise, a previous bug investigation should preserve whether “the timezone conversion caused it” was merely a hypothesis or a finding supported by references.

This illustrates the kind of record XMem supports; it is not a measured claim about model recall accuracy.

## Core capabilities

### Retrieve with project and task context

Engineering retrieval uses explicit project/workspace identity, task reference, task version, and role context. Select by files, modules, topics, or keywords. Preview results before expanding the selected record bodies.

Record references carry revision IDs and source/content/binding hashes. The consumer can inspect a record’s evidence rather than accept a free-floating summary as current truth.

### Preserve revisions instead of overwriting history

Capture includes the expected previous revision. Compare-and-swap checks help detect conflicting writes. Sources, applicability, and record content remain part of the stored engineering evidence.

Failure records distinguish observations, analysis status, and supporting references. Retraction/reconciliation operations preserve a way to inspect changed or withdrawn knowledge.

### Keep retrieval bounded and honest

Queries have result and payload limits. Incomplete coverage, missing sources, or uncertain results need to remain visible; a short preview is not equivalent to reading the complete evidence. Consumers should expand the records they actually adopt.

### Continue through explicit checkpoints

Save approved findings, read them back, and establish a checkpoint for the next session. Installation, session binding, a successful save, and later retrieval are separate events—each can be checked.

## Quick start

Current public source: **V0.1 community line · package `0.1.1` · MPL-2.0**. The documented joint setup pairs it with **XDev `0.1.2`**.

**For a configured Codex project, use [the X Suite Windows installation guide](https://github.com/NUVANU/X-Suite/blob/main/INSTALL.md).** Building a runtime alone does not initialize a project, establish consent, or enable memory permissions.

The published source-build path uses Windows x64, **Node.js 24.20.0**, and **npm 11.19.0**. From a clean XMem checkout:

```powershell
npm.cmd ci --ignore-scripts
npm.cmd run check
npm.cmd run build
node tools/stage-runtime.mjs C:\XSuite\xmem-runtime
Set-Location C:\XSuite\xmem-runtime
npm.cmd ci --omit=dev --ignore-scripts
```

The staging target must be a **new, absolute directory** separate from the source checkout. Keep that directory in place. The current package includes a pinned Windows x64 SQLite native dependency; other platforms require their own dependency/runtime validation.

The engineering MCP process entry, from the staged runtime, is:

```text
node dist/src/engineering-companion.js
```

Follow the guide for registration, project/storage initialization, source enrollment, and XDev integration. A fresh project may correctly return no historical records.

After setup, an example request to your coding agent is:

```text
Before changing the reservation module, retrieve relevant project memory.
Expand the records you plan to use and check their sources and applicability.
Keep historical rules and unresolved findings distinct from current decisions.
Save approved new findings, read them back, and checkpoint the handoff.
```

## Technical design

| Mechanism | What it provides |
| --- | --- |
| SQLite-backed local storage | Durable records, revisions, and transactional operations |
| Structured engineering records | Constraints, decisions, interfaces, failures, unknowns, and notes |
| Explicit file/module/topic associations | Select relevant project context without loading all history |
| Preview → expand | Inspect references first, then retrieve the selected evidence bodies |
| Revision and content hashes | Detect stale references and content/binding changes |
| Expected previous revision | Reject conflicting updates rather than silently overwrite them |
| Typed SDK + structured MCP adapter | Integrate through one core memory implementation |
| Project storage policy | Keep identity under `.xmem`, with project-local or explicitly selected custom local storage |

Useful source entry points: [engineering memory](src/engineering-memory.ts), [MCP schemas](src/engineering-mcp-contract.ts), [MCP adapter](src/engineering-mcp.ts), [storage policy](src/storage-location.ts), and [public package exports](package.json).

The XDev integration also verifies the deployed XMem program and manifest. Those **runtime integrity checks** are distinct from **memory record revision/source hashes**. Neither a package version nor a content hash proves that a remembered conclusion is correct.

## XMem and your coding host

XMem provides persistent evidence and retrieval. The host decides when to call it, how to present retrieved material to the model, and how to execute work. XDev can apply governance rules to the resulting workflow.

This is explicit engineering memory, separate from the host’s native memory feature. It does not promise automatic injection after every context compaction, complete capture of every conversation, or correct adoption by every model. A stored historical instruction is not fresh permission to run a task.

Bindings and roles help scope operations; they are not a claim of cryptographically authenticated human/agent identities or operating-system isolation.

## Privacy, upgrades, and current scope

Project configuration lives under `.xmem`; the actual database/artifacts can remain project-local or use an explicitly selected local directory. Changing storage after persisted memory exists requires a separate migration rather than silently switching locations.

The documented community path covers bounded local Windows/Codex saving, readback, and new-session retrieval. Other hosts, operating systems, unattended recovery paths, and newer local builds need separate verification. This README does not claim a benchmarked recall rate or token-saving percentage.

Memory is stored locally, but retrieved content may be sent to your host’s model provider. Save only sources you are authorized to use. Keep credentials, private conversations, and memory databases out of public repositories and issues.

When upgrading the joint deployment, create a new runtime directory and follow the matching deployment/manifest procedure. Do not replace a running database or assume a new package automatically migrates existing records.

## Contribute and report issues

Source checks:

```powershell
npm.cmd ci --ignore-scripts
npm.cmd run check
npm.cmd run build
```

For [issues](https://github.com/NUVANU/XMem/issues), include the version/commit, host/runtime, a minimal redacted example, and the distinction between expected and observed behavior. Identify whether the problem occurred at installation, binding, saving, readback, or retrieval.

Explore the combined workflow in [X Suite](https://github.com/NUVANU/X-Suite), or inspect the SDK exports and MCP contracts above for integration.

## License

[Mozilla Public License 2.0](LICENSE). Third-party components retain their own licenses.
