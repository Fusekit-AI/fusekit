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

## Open Acceptance Items

- Finish a full live Moonlite RSVP run where Cloudflare DNS, Resend domain/API key,
  Resend audience/from email, Vercel env vars, GitHub secrets, deployment, and live
  URL health all pass or are pending-safe without side-channel instructions.
- Reduce VNC usage by preferring provider APIs after login/consent, using the VNC
  only for real human gates such as login, MFA, CAPTCHA, consent, payment, and
  provider-owned copy-once secret screens.
- Record a clean new-site/new-account rehearsal and compare every human action
  against the control-room instructions before launch readiness is claimed.
