# Magic Path Friction Log

FuseKit's public promise is that the user logs in, approves real provider gates, and
then watches FuseKit do the work through the launcher/control-room surface. Any step
that requires the user to infer provider setup, paste side-channel commands, debug VM
state, or decide which provider page matters is a product bug until it is automated,
guided, or explicitly verified.

## Product Rules

- Provider gates must open inside the live VM browser session that FuseKit observes.
- Verification failures that require a human must create durable control-room gates
  with exact follow-me steps and the right provider URL.
- DNS changes are allowed only after explicit approval, then FuseKit applies the
  approved record shape and verifies propagation.
- Secrets must be captured only into the encrypted vault or provider-native secret
  stores; no launcher/control-room route may expose raw secret text.
- "I finished this step" must trigger a visible state transition: either reverify,
  surface the next guided gate, or show the exact remaining blocker.
- Every real-run intervention should become an audit event, regression test, or
  tracked backlog item before launch readiness is claimed.

## Logged Friction And Fixes

| Friction observed | Product fix |
| --- | --- |
| OCI launched ARM or too-small shapes that broke Python, uv, Node, OpenClaw, and browser runtime binaries. | Runner provisioning now prefers x86_64 Flex runners sized for visual/browser automation and rejects ARM fallback for the OCI lane. |
| SSH reachability failed on older clients due to unsupported SSH options and image-specific login users. | OCI bootstrap now resolves the image user and avoids brittle SSH algorithm options when the client cannot support them. |
| OCI compartment creation caused permission and cleanup churn. | The launcher can use the tenancy/root compartment path and must avoid unnecessary compartment creation for public runs. |
| Provider pages opened in a local browser instead of the VM browser FuseKit observes. | Control-room gate-open actions launch provider URLs in the shared VM browser profile. |
| noVNC/control-room loops made the user re-enter passwords or stare at a blank display. | Visual runtime readiness is surfaced as control-room state, and gates point users to the same VM browser session. |
| Cloudflare DNS approval and application happened outside the guided launcher path. | DNS approval is treated as a first-class approval gate; after approval FuseKit applies and verifies the exact records. |
| Resend account pages gave no exact instruction for API key, domain, audience ID, or from-email setup. | Verification-time Resend failures now create actionable control-room gates with Resend-specific follow-me steps. |
| "I finished this step" sometimes appeared to do nothing after a provider gate was passed. | Provider verification gates are regenerated from verification results, so the next missing capability becomes visible instead of hiding in the report. |
| Missing Vercel/GitHub runtime env values were reported as provider checks rather than guided Resend tasks. | Missing `RESEND_*` runtime values now route to a Resend runtime-values gate with exact capture instructions. |
| Copy-once provider secrets required side-channel capture after the user clicked Copy inside the VM. | Secret-bearing gates now show VM-clipboard capture buttons that write the selected value directly into the encrypted vault and return only redacted status. |
| Resend key verification returned `403` even when the key had full access. | Resend API verification now sends a `User-Agent`, avoiding false key-rejection gates. |
| Resend had no domain or audience after API auth was available. | Resend setup now runs before Cloudflare/DNS, creates or reuses the sending domain through Resend's API, creates an audience only when the app requires one, stores runtime values in the encrypted vault, and hands Resend DNS records to Cloudflare for approved apply/verify. |
| Launch proof could pass conceptually even if a run accidentally attempted DNS before Resend had emitted its domain records. | Live acceptance now records and checks provider strategy order; when Resend and DNS are both present, Resend must appear before Cloudflare/DNS or the run is not launch-ready. |
| Capture gates still told the user to click "I finished this step" even though the button is hidden for secret capture. | Capture-gate guidance now tells the user to copy inside the VM, click Capture, and let FuseKit auto-resume once every requested value is captured. |
| Generic gate ids could make the control room show generic provider guidance even when the gate record knew the provider. | Static and live control-room rendering now use the gate's `provider` field as the source of truth for guidance, with text inference only as a fallback. |
| The useful "verifying now" message could be replaced immediately by a generic live-refresh message. | Gate-pass refresh now preserves the explicit "Snowman is rechecking the provider now" status until the next real state appears. |
| Pending-safe DNS verification could look like vague waiting even when the remaining action was DNS approval/apply. | Verification cards now translate pending-safe DNS approval states into plain-language instructions to approve/apply the exact setup-plan records while FuseKit keeps verifying propagation. |
| Static control-room guidance and live-refresh guidance could drift because provider instructions were duplicated in Python and JavaScript. | Live control-room JavaScript now consumes the serialized Python guidance payload, so provider instructions have one source of truth across static and refreshed views. |
| Provider route cards exposed raw strategy names without explaining whether FuseKit was using deterministic automation or VM follow-me. | Provider route rows now translate selected strategies into plain-language summaries such as API automation, vault capture, or VM follow-me. |
| First-time provider authorization gates could tell the user a token was needed without rendering the safe Capture button, or capture a token under an ID the next setup loop did not read. | Authorization gates now carry the token env target and exact follow-me steps, and VM clipboard capture writes both the env-specific vault record and the canonical provider token alias used by deterministic setup. |
| Live launch proof could ignore durable control-room gate state, leaving a run marked ready even though the launcher still had a waiting provider gate. | Live acceptance now requires `gates.json` and fails unless every durable gate is resolved before launch readiness is claimed. |
| Acceptance proof could snapshot raw gate URLs from provider callbacks even though those URLs might contain provider-owned codes or token-like query parameters. | Live acceptance now writes a minimal redacted gate-state proof instead of raw browser/session URLs while still proving every gate is resolved. |
| Provider strategy proof could be too shallow to explain whether FuseKit used deterministic API automation, secure vault capture, or VM follow-me, making the control room feel like it skipped the important reasoning. | Live acceptance now requires complete selected-route evidence and considered candidates for every provider strategy decision before a run can be marked launch-ready. |
| Provider gates could tell the user what provider page to use but not the exact next action or what FuseKit would do after the click/capture, making the flow feel stuck even when the worker was alive. | Durable gate records now carry `next_action` and `resume_hint`, static/live control rooms render them, and live acceptance fails if any gate is missing guided next-step proof. |
| The noVNC password could be duplicated into frontend dataset state just to avoid iframe refreshes. | Live control-room refresh now compares the existing iframe URL instead of copying the password into extra DOM state; the password remains only in the autoconnect URL/copy affordance where needed. |
| Control-room gate open/resume/capture actions could be recorded in gate state without launch acceptance proving they were also in the audit ledger. | Live acceptance now requires every durable control-room gate to have a matching redacted `control_room.*` audit event before a run can be launch-ready. |
| Acceptance blockers were only visible in `.fusekit/acceptance/report.json`, so the launcher could still feel stuck when the order-of-operations proof failed. | Static and live control rooms now render `blockers[]` as launch-blocker cards with plain next actions, including Resend-before-DNS ordering failures. |
| Provider setup was sorted Resend-before-DNS but could still continue to downstream providers if Resend paused on an API-key gate, risking an incomplete DNS plan. | Provider setup now pauses at the first unresolved authorization gate, records that downstream providers are waiting, and resumes later with complete upstream provider data. |
| Provider verification could still run downstream DNS/deploy checks while an upstream provider gate was waiting, creating confusing failures before Resend had produced its domain records. | Provider verification now uses the same provider dependency order as setup and parks downstream providers as pending-safe behind the active gate. |
| Capture or "I finished this step" could feel inert because the worker was still sleeping for the full gate retry interval after the control room requested resume. | Gate waits now poll durable gate state and wake as soon as the control room marks a gate passed or resume-requested. |
| DNS apply approval could be visible in the control room but still depend on terminal input, so a launcher approval woke the worker without actually approving DNS. | DNS approval gates now accept the protected control-room approval state, use an explicit "Approve DNS apply" button, and continue directly into provider DNS apply/verify. |
| After approving setup or DNS, the control room could still say FuseKit was retrying generic provider verification, making the user wonder whether the approval actually applied the right thing. | Resume-requested gates now carry setup/DNS-specific next-action and status copy across static HTML, live refresh, and POST responses. |
| Resend DNS records can return provider-managed TTL values such as `Auto`, which could break parsing before Cloudflare received the record plan. | Resend DNS record parsing now treats provider-managed TTL values as the safe default TTL while preserving record name, type, value, and priority. |
| Resend runtime repair could send the user to Audiences even when the only missing value was the verified sender address, and mixed provider messages could leak non-Resend env names into the Resend capture gate. | Resend runtime gates now target only `RESEND_*` values and route the user to Domains, Audiences, or API Keys based on the exact missing Resend value list. |
| Cloudflare token creation exposed many permission, resource, IP filtering, and TTL choices with too little guidance for a no-thinking demo. | Cloudflare gates now spell out the exact Custom token wizard choices: two permission rows, one specific zone, blank IP filtering/TTL unless required, then Continue to summary/Create Token. |
| Provider strategy gates generated useful next-action copy but the durable gate recorder dropped it, forcing the launcher back to generic instructions. | Provider strategy gates now persist their specific next action and resume hint into `gates.json`, so the control room can show the intended follow-me instruction. |

## Open Acceptance Items

- Finish a full live Moonlite RSVP run where Cloudflare DNS, Resend domain/API key,
  Resend audience/from email, Vercel env vars, GitHub secrets, deployment, and live
  URL health all pass or are pending-safe without side-channel instructions.
- Reduce VNC usage by preferring provider APIs after login/consent, using the VNC
  only for real human gates such as login, MFA, CAPTCHA, consent, payment, and
  provider-owned copy-once secret screens.
- Record a clean new-site/new-account rehearsal and compare every human action
  against the control-room instructions before launch readiness is claimed.
