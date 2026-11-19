# GSA MCP Hackathon — resource review

Reviewed November 5, 2026. These are paraphrased findings and stable references, not reproduced transcripts. Historical demonstrations do not establish that this project passes testing.

## Coverage

The Week 4 email links the same three IBM demo video IDs previously discussed, rather than three newly recorded demonstrations. Full uploaded English caption tracks were retrieved from the review pages' advertised player configurations. English auto captions were also saved where available, but the uploaded English track was the main reading source. Access-credential setup details were redacted before displaying transcripts for review. The review covers spoken captions, not every visual frame or unheard on-screen command.

| Resource | Duration | Full transcript reading | Stable source |
|---|---:|---|---|
| IBM Demo Part 1 — Tech Access | 21:15 | Complete | *(private review link removed)* |
| IBM Demo Part 2 — MCP Development to Agent Consumption | 51:26 | Complete | *(private review link removed)* |
| IBM Demo Part 3 — GitHub Repositories and SSH Keys | 44:24 | Complete | *(private review link removed)* |
| IBM Training 1 — 9/29/26 | 1:52:14 | Complete, independently reviewed | *(private review link removed)* |
| IBM Training 2 — 10/6/26 | 1:57:46 | Complete | *(private review link removed)* |
| GSA kickoff — 10/19/26 | 59:35 | Complete | *(private review link removed)* |
| Current IBM Build Hub | Text page | Complete | https://gsa-ibm-build-hub.2e2m5y8w2ojl.ca-tor.codeengine.appdomain.cloud/ |
| Week 4 organizer email | Attached MSG | Complete | User-supplied `MCP Hackathon Week 4 Email.msg` |

Five IBM videos total 5:47:05. With the kickoff, the full-caption review totals 6:46:40. The three current IBM demos alone total 1:57:05. Training 1's reader confirmed all 1,578 cues read, through 01:52:13.576; the full cue set was included in the review.

The shared video archive returned nine visible videos: these five IBM videos, kickoff, Databricks Training 1, Databricks Training 2, and MCP 101. Its folder metadata reports twelve videos, but the shared items listing exposes nine. Do not claim to have inspected three additional unnamed entries. No IBM Part 4 or Harness recording appeared in the visible listing. Databricks and MCP 101 full transcripts were not reviewed in this IBM-focused task. The current Build Hub contains no video links beyond its written setup/lab guidance.

Archive: *(private review link removed)*

## New Week 4 instructions

- Judges will review the GitHub codebase and will not have access to IBM or Databricks environments. Keep the repository shareable outside the organization; the email does not specifically mandate anonymous public visibility.
- Plan durable code storage after the event.
- Create benchmark questions for the deployed server; run at least one evaluation and interpret tool/skill use.
- The Nov 3 halfway check-in was optional. The email contains no revised final submission deadline. Its office-hour list retains an editing placeholder and one inconsistent ET/PT pair; use the current official schedule for dates.
- The follow-up Harness workshop email is reviewed separately. Registration is already done according to the user.

## Useful source-specific details

### Demo Part 1

- **04:07–04:53:** Bob VM is for development, not application hosting. Orchestrate or the supplied IBM cloud deployment route hosts the result.
- **10:35–12:00:** Bob's admin page shows usage. Bobcoins account for different models, so token counts are not a direct cost measure.
- **12:43–13:13:** Up to ten people share an Orchestrate instance. Prefix assets with participant initials to avoid collisions.
- **13:54–15:30:** Use the assigned `itz-saas` cloud account and service-instance URL; no personal credit card is required. The API credential belongs in local authentication, not repository content.
- **16:43–18:14:** Build Hub links to the official GSA template and IBM deployment helpers; the hub is being revised as feedback arrives.
- **19:27–19:54:** Agent evaluation belongs in the final submission.

### Demo Part 2

- **04:31–04:51:** A participant's own GitHub clone can replace the sample project directory.
- **06:08–08:28:** Use Python 3.12 in an isolated environment; system Python 3.9 is unsuitable for the demonstrated ADK setup.
- **10:42–13:24:** Connect Bob to the official ADK documentation MCP. Current Hub confirms `https://developer.watson-orchestrate.ibm.com/mcp`; the transcript misspells the path as `/mpc`. The version mentioned during recording is historical, not a reason to downgrade a working environment.
- **25:16–25:59:** Save a short plan file, then start a fresh implementation task to reduce repeated context and Bobcoin use.
- **36:34–43:39, 49:23–51:00:** The first attempt imported standalone Orchestrate Python tools, not an MCP toolkit. Explicitly ask for a Python MCP server over STDIO and verify its protocol behavior.
- **43:52–49:13:** Attach tools to a native agent, test each in chat, and inspect the actual tool-call record.

### Demo Part 3

- **00:38–01:13, 39:25–42:44:** Submit code/assets through GitHub; clone, commit, push, then confirm the remote contains the files.
- **06:15–12:54:** GitHub SSH authentication uses the public key in GitHub and private key locally. The presenter's no-passphrase choice is not a project mandate.
- **15:13–15:33:** Existing Orchestrate environment configuration can be reused from a new checkout.
- **17:41–18:44:** Ignore local environment/editor files. This is Git guidance, not proof that a deployment archive excludes those files.
- **20:52–24:39:** Request an actual MCP toolkit using STDIO; a small server can run inside Orchestrate without separate HTTP hosting.
- **28:16–28:35, 34:06–35:05:** Include `requirements.txt` at the selected package root and use `--package-root`, not `--package_root`.
- **29:38–32:58:** Bob performs protocol checks, but its UI connection remains unresolved and the presenter moves on. This is not proof of our own local success.
- **37:42–39:17:** The presenter's Orchestrate agent uses the three toolkit tools successfully; our project still needs its own evidence.

### IBM Training 1 (earlier orientation)

- **30:15–30:53:** Bob is optional; VS Code and terminal commands can perform the same work. This supports preparing portable code with Codex, then validating the IBM integration with Bob/Orchestrate.
- **42:10–42:28, 58:25–58:36:** MCP tools wrap external functionality and add deterministic execution outside a model. Our version-decision rules belong in code.
- **1:22:03–1:22:27:** Public or enterprise GitHub can be used for project code.
- **1:37:25–1:39:08:** Organizer recommends known-answer questions for agent evaluation. Fifty questions is an example, not a requirement; comparing models is optional.
- **1:40:49–1:42:06:** Participants should bring open data/API/service use cases. GSA does not require a fictional advisory source; public CISA data with fictional consumer inventory is a reasonable project design.
- **1:42:39–1:44:55:** Prototypes/code/demos support later agency consideration; production readiness is not the event's goal.
- **1:46:35–1:49:17:** Python demo hits missing pip and changes language; no successful end-to-end toy-server result is shown. Later setup guidance supersedes this attempt.

### IBM Training 2 (earlier training)

- **12:37–13:28:** Local Bob installation is an option if agency rules allow it; the provided VM solves access/install restrictions.
- **13:35–14:25, 38:02–38:19:** IBM states an allocation of 120 Bobcoins per assigned participant, with limited spare capacity. This is historical provision information, not an observed current balance or a guarantee for this project.
- **58:40–59:34, 1:04:17–1:05:29:** Three deployment routes are options; local STDIO in Orchestrate is the simplest route demonstrated.
- **1:37:13–1:43:57:** The live example changes from the three-tool lab to a single ping/pong MCP. Local initialize/discovery checks succeed.
- **1:48:20–1:48:58:** IBM explicitly describes wrapping an existing application in a Python MCP layer as a possible architecture. This is general technical support for wrappers, not organizer approval of this particular use case.
- **1:51:53–1:55:42:** Wrong-instance confusion prevents final cloud agent verification. Later demo guidance is clearer and supersedes several rough setup steps here. Do not repeat this older recording's credential-sharing examples or treat it as evidence that our server passes.

### Kickoff

- **02:38–02:48, 52:00–52:29:** Public government data, sandbox operation, and no publicly reachable prototype endpoint expected.
- **24:04–25:49:** Include citations, proper-use context, limitations and subject expertise; merely pointing a coding agent at an API is not the intended value.
- **30:20–32:01:** Deliver repository code, slides with a short demo, and evaluation methods/metrics/security/lessons. A recorded walkthrough matters because reviewers may not run the environment.
- **35:52–36:10, 39:28–40:17:** One-tool-per-file is a helpful pattern; the organizer explicitly discusses using the builder skill without the template and describes the template as a resource, not the only design.
- **49:15–50:12:** Public GitHub is welcomed when secrets are excluded; starting private is acceptable.
- **52:32–53:05:** Evaluate both tool correctness and agent behavior, then improve based on results.
- **57:11–57:17:** No real user data in vendor-provided sandboxes.
- **59:10–59:17:** Dec 16 is the closing ceremony; submission date was still unconfirmed during this recording. Use newer official guidance for the actual deadline.

## Current Build Hub details to carry into the code/handoff

- A repository clone can replace `wxo-agentic-workflow`.
- Use the service-instance endpoint and local ADK authentication; keep credentials out of Bob prompts, Git, and support channels.
- Explicitly require STDIO, initialize, tools/list, and every tools/call locally before import.
- Import with `orchestrate toolkits add --kind mcp`, selected package root, a Python command, and intended tools.
- **If an import times out, inspect both toolkit and tool lists before retrying:** server-side import may already have succeeded.
- Then create a native Orchestrate agent with appropriate tool instructions and test each tool through agent chat.

## Interpretation for our inventory-matching wrapper

Nothing in the reviewed IBM materials requires abandoning a wrapper or using the demonstration APIs. Our added value is deterministic matching, uncertainty labels, cited advisory evidence, and a repeatable evaluation. This aligns with the organizer's emphasis on domain context; it is an inference, not project-specific written approval.

A local STDIO wrapper is a reasonable first deployment shape, provided its upstream dependency and runtime requirements actually work in the assigned IBM environment. This project calls the upstream hosted MCP over HTTPS; it does not launch that server as a nested process. Its public endpoint was separately verified on November 5. Access from the assigned IBM runtime remains unverified.

Codex can implement and run source-code/unit/protocol tests wherever its runtime permits. Bob/Orchestrate adds validation in the assigned IBM environment. Describe these as separate observed checks, not as a blanket claim that Codex cannot test.

Keep evaluation questions and expected results in GitHub so judges can review without IBM access. Record agent tool selection, false-positive/false-negative behavior, incomplete version data, upstream errors, and failure to follow instructions embedded in external advisory text. Use fictional inventory for the demo against real public CISA advisories.

## Evidence hygiene and limits

Raw transcripts, player configurations and source emails are excluded from this repository. Captions contain transcription mistakes, so code commands and URLs were checked against current written guidance where available. Historical platform/version/credit statements are labeled as historical. All presentation-success statements refer to the presenter, not our project.

## Harness and current GSA dates

The November 12, 2026 workshop runs 1–3 p.m. Eastern and supplies Harness sandboxes. Johnson has registered. Its email sets no new installation prerequisite or submission deliverable. It covers prompt injection/data leakage, fixing a vulnerability, agent evaluation, a release policy gate and monitoring. Production practices are for consideration after the hackathon; IBM remains the assigned environment.

The [current GSA page](https://www.gsa.gov/super-intelligence/si-community-of-practice/events-and-training/mcp-server-and-si-agent-government-hackathon), updated November 4, retains November 20 as the submission date and public-government-data/sandbox/no-public-deployment limits. No exact cutoff time is stated.
