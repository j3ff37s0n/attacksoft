# Attacksoft.com

Allows users to submit anything and get an analysis level extrapolation based on all processes captured from running it on a sandbox.

## Highlight

You submit a file. It runs inside an isolated VM. Every process, file drop, network connection, and registry change the sample makes is captured. That raw process log becomes the evidence base for three reports:

- Executive risk summary
- Attack chain timeline
- Remediation checklist

The reports aren't free-form LLM output. Every claim has to be verbatim-cited back to captured evidence. A deterministic verifier rejects anything that isn't. If a report says "the sample dropped X in `C:\Users\...`", it must point at the captured event that says exactly that.

There's also an intel dashboard that ranks CVEs against your environment instead of by raw CVSS.

## Network

Ingress: user request -> cloudflare tunnel -> nginx proxy management -> vlan isolation -> services/applications

Egress: application response -> vlan isolation -> nginx proxy management -> cloudflare tunnel -> user

Nothing binds to a public IP. The only way in is the cloudflare tunnel. The tunnel terminates at nginx, nginx routes to internal services, and the services sit on their own VLAN.

A compromised webapp can't reach the pipeline except through the token-authenticated API. A compromised pipeline can't reach the internet — it can only reach ollama on loopback and cuckoo over a dedicated SSH key.

## Main processing is done on VMs

- **webapp (VM A)** — flask + gunicorn. intake, report proxy, intel dashboard, stripe webhooks.
- **pipeline (VM B)** — fastapi. stages the file, submits to cuckoo, fetches artifacts, runs the LLMs, verifies citations, renders PDFs.
- **cuckoo (VM C)** — the sandbox itself. 5 analysis VMs across windows and linux.

How they talk to each other:
webapp -> pipeline HMAC-compared service token
pipeline -> cuckoo dedicated SSH key (cuckoo_key)
cuckoo -> analysis VMs role-based restricted access on proxmox
The SSH key on the pipeline is only authorized for the specific sandbox user on cuckoo. Role-based access on cuckoo lets the controller push a sample and collect output, but no other access (resets to snapshot and can stop machine, no other rights)

## Analysis Security

**The sample never runs on infrastructure that has anything to lose.** It runs inside an analysis VM. The pipeline submits it over SSH, waits, pulls artifacts, kills the VM. The webapp and pipeline hosts never execute it.

**Everything is local.** Inference runs on ollama on the pipeline VM. No API calls to OpenAI, Anthropic, Google, or anyone else. Your file never leaves your network, and neither does the analysis.

**Everything gets deleted on a schedule.** The upload is deleted at completion. Cuckoo's copy is deleted right after artifact fetch. Pipeline working artifacts are purged 3 hours after completion. RSS cache prunes at 30 days. SQLite WAL is disabled so no stale pages linger on disk.

**No raw IPs stored.** Only HMAC'd hashes. You can't reconstruct a client IP from the database.

**Stripe webhooks are signature-verified.** State only changes after the webhook signature validates against the stored secret.

**Session cookies are HttpOnly + SameSite=Lax.** CSRF is blocked at the cookie layer, plus an Origin check on state-changing routes.

**Service-to-service auth is HMAC-compared with a constant-time compare.** The pipeline doesn't trust anything the webapp says without it.

## What this doesn't protect against

- This is for reports, not a threat modeling scanner. The signature set is customized but not comprehensive.
- Hardened again sandbox escape. The isolation is VM-level and hardware level via firewalls. Wouldn't produce full logs if escaped.



