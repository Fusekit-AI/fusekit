"""Control-room CSS assets."""

from __future__ import annotations

STYLE = r"""
:root {
  color-scheme: light;
  font-family:
    Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
  --snow-navy: #00152a;
  --snow-deep: #020b18;
  --snow-blue: #0097ff;
  --snow-blue-dark: #0067d9;
  --snow-ice: #eef8ff;
  --snow-panel: rgba(255, 255, 255, 0.82);
  --snow-line: rgba(0, 151, 255, 0.18);
  --snow-ink: #071525;
  --snow-muted: #60738a;
  background: var(--snow-ice);
  color: var(--snow-ink);
}

* {
  box-sizing: border-box;
}

html {
  min-width: 320px;
}

body {
  min-width: 320px;
  margin: 0;
  overflow-x: hidden;
  background:
    radial-gradient(circle at 76% 4%, rgba(0, 151, 255, 0.22), transparent 28%),
    radial-gradient(circle at 10% 22%, rgba(0, 103, 217, 0.12), transparent 26%),
    linear-gradient(90deg, rgba(0, 21, 42, 0.04) 1px, transparent 1px),
    linear-gradient(180deg, rgba(0, 21, 42, 0.04) 1px, transparent 1px),
    var(--snow-ice);
  background-size: 100% 100%, 100% 100%, 42px 42px, 42px 42px;
}

.shell {
  width: 100%;
  max-width: 1480px;
  margin: 0 auto;
  padding: 34px;
  overflow: hidden;
}

.hero {
  min-width: 0;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 28px;
  padding-bottom: 28px;
  border-bottom: 2px solid var(--snow-navy);
}

.brand-lockup {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  min-height: 48px;
}

.brand-mark {
  position: relative;
  width: 44px;
  height: 44px;
  border-radius: 8px;
  background: var(--snow-navy);
  box-shadow: inset 0 0 0 1px rgba(0, 151, 255, 0.22);
}

.mark-hat,
.mark-head,
.mark-node {
  position: absolute;
  background: var(--snow-blue);
  box-shadow: 0 0 16px rgba(0, 151, 255, 0.38);
}

.mark-hat {
  width: 20px;
  height: 14px;
  top: 5px;
  left: 12px;
  border-radius: 4px 4px 2px 2px;
}

.mark-hat::after {
  content: "";
  position: absolute;
  width: 28px;
  height: 5px;
  left: -4px;
  top: 12px;
  border-radius: 999px;
  background: inherit;
}

.mark-head {
  width: 18px;
  height: 18px;
  top: 21px;
  left: 14px;
  border-radius: 50%;
  background: transparent;
  border: 4px solid var(--snow-blue);
}

.mark-node {
  width: 7px;
  height: 7px;
  border-radius: 50%;
}

.mark-node::before {
  content: "";
  position: absolute;
  width: 16px;
  height: 3px;
  left: -14px;
  top: 2px;
  border-radius: 999px;
  background: var(--snow-blue);
  transform-origin: right center;
}

.mark-node-a {
  left: 7px;
  top: 26px;
}

.mark-node-a::before {
  transform: rotate(34deg);
}

.mark-node-b {
  left: 9px;
  top: 36px;
}

.mark-node-b::before {
  transform: rotate(-36deg);
}

.mark-node-c {
  right: 6px;
  bottom: 5px;
}

.brand-copy {
  display: grid;
  gap: 1px;
}

.brand-copy strong {
  color: var(--snow-navy);
  font-size: 17px;
}

.brand-copy span {
  color: var(--snow-muted);
  font-size: 12px;
  font-weight: 850;
  text-transform: uppercase;
}

.eyebrow,
.section-kicker {
  color: var(--snow-muted);
  font-size: 12px;
  font-weight: 850;
  letter-spacing: 0;
  text-transform: uppercase;
}

h1,
h2,
p {
  margin: 0;
}

h1 {
  max-width: 760px;
  margin-top: 8px;
  font-size: 58px;
  line-height: 1;
  letter-spacing: 0;
  overflow-wrap: anywhere;
}

.hero p {
  max-width: 820px;
  margin-top: 14px;
  color: #31465c;
  font-size: 16px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

code {
  border: 1px solid rgba(0, 21, 42, 0.12);
  border-radius: 6px;
  padding: 2px 6px;
  background: rgba(255, 255, 255, 0.72);
  color: var(--snow-ink);
  font: 0.94em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  overflow-wrap: anywhere;
}

.status-stack {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  min-width: 260px;
}

.pill,
.badge,
.live-pill,
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 32px;
  border: 1px solid rgba(0, 21, 42, 0.14);
  border-radius: 999px;
  padding: 7px 11px;
  background: rgba(255, 255, 255, 0.72);
  color: #15304c;
  font-size: 12px;
  font-weight: 850;
  white-space: nowrap;
}

.pill.status {
  border-color: transparent;
  color: var(--snow-ink);
}

.pill.muted,
.live-pill {
  color: var(--snow-muted);
}

.pill.refresh-ok {
  border-color: rgba(54, 127, 54, 0.24);
  color: #1f5e28;
}

.pill.refresh-stale {
  border-color: rgba(172, 92, 18, 0.26);
  background: #fff0cf;
  color: #74420f;
}

.overview {
  min-width: 0;
  display: grid;
  grid-template-columns: minmax(0, 0.9fr) minmax(360px, 1.1fr);
  gap: 18px;
  margin-top: 22px;
}

.progress-panel,
.focus-panel,
.timeline,
.artifact-panel {
  min-width: 0;
  border: 1px solid rgba(0, 151, 255, 0.14);
  border-radius: 8px;
  background: var(--snow-panel);
  box-shadow: 0 28px 70px rgba(0, 21, 42, 0.1);
}

.progress-panel,
.focus-panel {
  padding: 18px;
}

.panel-top,
.section-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 18px;
}

.panel-top strong {
  font-size: 13px;
}

.meter {
  height: 14px;
  margin: 28px 0 14px;
  overflow: hidden;
  border-radius: 999px;
  background: rgba(0, 21, 42, 0.09);
}

.meter span {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, var(--snow-blue), #6fd7ff);
  transition: width 220ms ease;
}

.stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.stats span {
  min-height: 54px;
  border: 1px solid rgba(0, 151, 255, 0.14);
  border-radius: 8px;
  padding: 10px;
  color: #536b82;
  background: rgba(255, 255, 255, 0.52);
  font-size: 12px;
  font-weight: 800;
}

.stats strong {
  display: block;
  color: var(--snow-navy);
  font-size: 22px;
  line-height: 1;
}

.focus-panel {
  overflow: hidden;
  background:
    radial-gradient(circle at 84% 12%, rgba(0, 151, 255, 0.28), transparent 30%),
    linear-gradient(135deg, var(--snow-navy), var(--snow-deep));
  color: #f7fbff;
}

.focus-panel.gate {
  background:
    radial-gradient(circle at 82% 10%, rgba(0, 151, 255, 0.32), transparent 32%),
    linear-gradient(135deg, #001f3f, #04101e);
}

.focus-panel .section-kicker,
.focus-panel p,
.next-line span {
  color: #bfc7c1;
}

.gate-help {
  position: relative;
  display: grid;
  gap: 9px;
  margin: 16px 0 0;
  border: 1px solid rgba(111, 215, 255, 0.22);
  border-radius: 8px;
  padding: 14px 14px 14px 58px;
  background: rgba(255, 255, 255, 0.08);
}

.gate-help::before {
  content: "";
  position: absolute;
  left: 17px;
  top: 20px;
  width: 23px;
  height: 23px;
  border-radius: 50%;
  background: #ffffff;
  box-shadow:
    0 22px 0 6px #ffffff,
    inset -4px -4px 0 #d9efff,
    0 0 18px rgba(111, 215, 255, 0.34);
  animation: gate-nod 1.8s ease-in-out infinite;
}

.gate-help::after {
  content: "";
  position: absolute;
  left: 19px;
  top: 12px;
  width: 19px;
  height: 9px;
  border-radius: 5px 5px 2px 2px;
  background: var(--snow-blue);
  box-shadow: 0 0 12px rgba(111, 215, 255, 0.48);
  animation: gate-hat 1.8s ease-in-out infinite;
}

.gate-help span {
  color: #9bdcff;
  font-size: 11px;
  font-weight: 900;
  text-transform: uppercase;
}

.gate-classification {
  width: fit-content;
  border: 1px solid rgba(111, 215, 255, 0.28);
  border-radius: 999px;
  padding: 3px 8px;
  background: rgba(111, 215, 255, 0.12);
}

.gate-help strong {
  color: #ffffff;
  font-size: 15px;
}

.gate-help p,
.gate-help em,
.gate-help li,
.gate-target {
  color: #d7e7f2;
  font-size: 13px;
  line-height: 1.45;
}

.gate-target strong {
  color: #ffffff;
}

.gate-help ol {
  display: grid;
  gap: 7px;
  margin: 0;
  padding-left: 20px;
}

.gate-help em {
  color: #b7e8ff;
  font-style: normal;
  font-weight: 850;
}

.gate-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.gate-link,
.gate-attempts {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  border-radius: 999px;
  padding: 6px 10px;
  background: rgba(255, 255, 255, 0.12);
  color: #f7fbff;
  font-size: 12px;
  font-weight: 850;
  text-decoration: none;
}

.gate-link {
  border: 1px solid rgba(111, 215, 255, 0.34);
}

.gate-done {
  justify-self: start;
  min-height: 36px;
  border: 0;
  border-radius: 8px;
  padding: 9px 13px;
  background: #ffffff;
  color: var(--snow-navy);
  font-weight: 900;
  box-shadow: 0 10px 24px rgba(0, 0, 0, 0.22);
}

.gate-done:disabled {
  opacity: 0.72;
}

.snow-scene {
  position: relative;
  min-height: 136px;
  margin: 18px 0 4px;
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 8px;
  background:
    linear-gradient(120deg, rgba(255, 255, 255, 0.08), transparent),
    radial-gradient(circle at 74% 25%, rgba(0, 151, 255, 0.22), transparent 34%);
}

.snow-scene::before {
  content: "";
  position: absolute;
  inset: auto 18px 20px 108px;
  height: 2px;
  border-radius: 999px;
  background: linear-gradient(90deg, transparent, rgba(111, 215, 255, 0.82), transparent);
  animation: data-wave 2.8s ease-in-out infinite;
}

.snowman {
  position: absolute;
  left: 26px;
  bottom: 18px;
  width: 86px;
  height: 94px;
  animation: snow-bob 2.4s ease-in-out infinite;
}

.snow-head,
.snow-body,
.snow-hat,
.arm,
.privacy-mitten,
.puddle,
.steam {
  position: absolute;
}

.snow-head {
  width: 39px;
  height: 39px;
  left: 24px;
  top: 14px;
  border-radius: 50%;
  background: #ffffff;
  box-shadow: inset -6px -7px 0 #d9efff;
}

.snow-body {
  width: 60px;
  height: 54px;
  left: 13px;
  bottom: 0;
  border-radius: 48% 48% 42% 42%;
  background: #ffffff;
  box-shadow: inset -8px -9px 0 #d9efff;
}

.snow-hat {
  width: 34px;
  height: 20px;
  left: 26px;
  top: 1px;
  border-radius: 6px 6px 2px 2px;
  background: var(--snow-blue);
  box-shadow: 0 0 18px rgba(0, 151, 255, 0.4);
}

.snow-hat::after {
  content: "";
  position: absolute;
  width: 44px;
  height: 7px;
  left: -5px;
  top: 17px;
  border-radius: 999px;
  background: var(--snow-blue);
}

.eye {
  position: absolute;
  width: 4px;
  height: 4px;
  top: 14px;
  border-radius: 50%;
  background: var(--snow-navy);
}

.eye.left {
  left: 12px;
}

.eye.right {
  right: 12px;
}

.nose {
  position: absolute;
  width: 13px;
  height: 5px;
  left: 19px;
  top: 21px;
  border-radius: 999px;
  background: #ff9f2e;
}

.privacy-mitten {
  z-index: 2;
  width: 15px;
  height: 12px;
  top: 10px;
  border-radius: 999px 999px 7px 7px;
  background: var(--snow-blue);
  box-shadow:
    inset -3px -3px 0 rgba(0, 21, 42, 0.16),
    0 0 12px rgba(111, 215, 255, 0.42);
  opacity: 0;
  transform: translateY(7px) scale(0.75);
  transition:
    opacity 180ms ease,
    transform 180ms ease;
}

.privacy-mitten.left {
  left: 6px;
  transform: rotate(-16deg) translateY(7px) scale(0.75);
}

.privacy-mitten.right {
  right: 6px;
  transform: rotate(16deg) translateY(7px) scale(0.75);
}

.button {
  position: absolute;
  width: 5px;
  height: 5px;
  left: 27px;
  border-radius: 50%;
  background: var(--snow-blue-dark);
}

.button.one {
  top: 18px;
}

.button.two {
  top: 32px;
}

.arm {
  width: 32px;
  height: 4px;
  top: 49px;
  border-radius: 999px;
  background: #7e5a38;
}

.arm.left {
  left: 1px;
  transform: rotate(-22deg);
}

.arm.right {
  right: 0;
  transform: rotate(24deg);
  transform-origin: left center;
}

.snow-prop {
  position: absolute;
  left: 124px;
  right: 18px;
  bottom: 22px;
  color: #d5ecff;
  font-size: 13px;
  font-weight: 850;
  line-height: 1.35;
  overflow-wrap: anywhere;
  white-space: normal;
}

.snow-prop::before {
  content: "";
  display: inline-block;
  width: 8px;
  height: 8px;
  margin-right: 8px;
  border-radius: 50%;
  background: var(--snow-blue);
  box-shadow: 0 0 14px rgba(0, 151, 255, 0.65);
}

.state-gate .arm.right {
  animation: snow-wave 1.1s ease-in-out infinite;
}

.state-gate .snow-prop::after {
  content: "  · Tap the provider prompt, then I keep going.";
  color: rgba(255, 255, 255, 0.68);
}

.state-privacy .privacy-mitten {
  opacity: 1;
}

.state-privacy .privacy-mitten.left {
  animation: privacy-peek-left 2.4s ease-in-out infinite;
  transform: rotate(-16deg) translateY(0) scale(1);
}

.state-privacy .privacy-mitten.right {
  animation: privacy-peek-right 2.4s ease-in-out infinite;
  transform: rotate(16deg) translateY(0) scale(1);
}

.state-privacy .arm.left {
  transform: rotate(-42deg) translate(18px, -12px);
}

.state-privacy .arm.right {
  transform: rotate(42deg) translate(-18px, -12px);
}

.state-privacy .snow-prop::after {
  content: "  · Hidden prompts and vault encryption keep secrets yours.";
  color: rgba(255, 255, 255, 0.72);
}

.state-working .snow-hat,
.state-launch .snow-hat {
  animation: hat-tap 1.4s ease-in-out infinite;
}

.state-verify .snowman::after {
  content: "";
  position: absolute;
  width: 25px;
  height: 25px;
  right: -14px;
  top: 35px;
  border: 4px solid #bfe8ff;
  border-radius: 50%;
  box-shadow: 0 0 14px rgba(0, 151, 255, 0.35);
}

.state-verify .snowman::before {
  content: "";
  position: absolute;
  width: 20px;
  height: 4px;
  right: -24px;
  top: 62px;
  border-radius: 999px;
  background: #bfe8ff;
  transform: rotate(42deg);
}

.state-repair .arm.left {
  animation: snow-fix 0.9s ease-in-out infinite;
}

.state-detonate .snow-head,
.state-detonate .snow-body {
  animation: snow-melt 2.2s ease-in-out infinite;
}

.state-detonate .puddle {
  width: 76px;
  height: 16px;
  left: 5px;
  bottom: -2px;
  border-radius: 50%;
  background: rgba(157, 222, 255, 0.52);
  animation: puddle-grow 2.2s ease-in-out infinite;
}

.state-detonate .steam {
  width: 3px;
  height: 24px;
  bottom: 52px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.74);
  opacity: 0;
}

.state-detonate .steam.one {
  left: 34px;
  animation: steam-rise 1.8s ease-in-out infinite;
}

.state-detonate .steam.two {
  left: 50px;
  animation: steam-rise 1.8s ease-in-out 0.4s infinite;
}

.state-done .snowman {
  animation: snow-celebrate 0.9s ease-in-out infinite;
}

@keyframes data-wave {
  0%, 100% { transform: translateX(-16px); opacity: 0.42; }
  50% { transform: translateX(18px); opacity: 1; }
}

@keyframes snow-bob {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-5px); }
}

@keyframes snow-wave {
  0%, 100% { transform: rotate(18deg); }
  50% { transform: rotate(-30deg); }
}

@keyframes privacy-peek-left {
  0%, 100% { transform: rotate(-16deg) translateY(0) scale(1); }
  55% { transform: rotate(-11deg) translateY(-1px) scale(1.02); }
}

@keyframes privacy-peek-right {
  0%, 100% { transform: rotate(16deg) translateY(0) scale(1); }
  55% { transform: rotate(11deg) translateY(-1px) scale(1.02); }
}

@keyframes hat-tap {
  0%, 100% { transform: rotate(0); }
  50% { transform: rotate(-5deg) translateY(-2px); }
}

@keyframes snow-fix {
  0%, 100% { transform: rotate(-22deg); }
  50% { transform: rotate(14deg); }
}

@keyframes snow-melt {
  0%, 100% { transform: scaleY(1); opacity: 1; }
  50% { transform: scaleY(0.7) translateY(16px); opacity: 0.72; }
}

@keyframes puddle-grow {
  0%, 100% { transform: scaleX(0.7); opacity: 0.3; }
  50% { transform: scaleX(1); opacity: 0.75; }
}

@keyframes steam-rise {
  0% { transform: translateY(12px); opacity: 0; }
  40% { opacity: 0.8; }
  100% { transform: translateY(-22px); opacity: 0; }
}

@keyframes snow-celebrate {
  0%, 100% { transform: rotate(-2deg) translateY(0); }
  50% { transform: rotate(3deg) translateY(-5px); }
}

@keyframes gate-nod {
  0%, 100% { transform: translateY(0) rotate(-2deg); }
  50% { transform: translateY(3px) rotate(3deg); }
}

@keyframes gate-hat {
  0%, 100% { transform: translateY(0) rotate(-2deg); }
  50% { transform: translateY(3px) rotate(3deg); }
}

.focus-panel h2 {
  margin-top: 28px;
  font-size: 32px;
  line-height: 1.05;
  letter-spacing: 0;
  overflow-wrap: anywhere;
}

.focus-panel p {
  max-width: 760px;
  margin-top: 12px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

.mini-dot {
  flex: 0 0 auto;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #8d9691;
  box-shadow: 0 0 0 5px rgba(141, 150, 145, 0.14);
}

.next-line {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 28px;
}

.next-line strong {
  color: #ffffff;
  overflow-wrap: anywhere;
}

.workspace {
  min-width: 0;
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
  gap: 18px;
  margin-top: 18px;
}

.recovery-panel {
  min-width: 0;
  margin-top: 18px;
  border: 1px solid rgba(0, 151, 255, 0.14);
  border-radius: 8px;
  padding: 20px;
  background: rgba(255, 255, 255, 0.76);
  box-shadow: 0 22px 52px rgba(0, 21, 42, 0.08);
}

.checkpoint-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.checkpoint-card {
  display: grid;
  grid-template-columns: 48px minmax(0, 1fr);
  gap: 12px;
  min-height: 172px;
  border: 1px solid rgba(17, 22, 21, 0.11);
  border-radius: 8px;
  padding: 12px;
  background: rgba(255, 255, 255, 0.72);
}

.checkpoint-card.running,
.checkpoint-card.waiting,
.checkpoint-card.failed {
  background: #ffffff;
}

.checkpoint-card span,
.checkpoint-card em,
.checkpoint-card code,
.checkpoint-card p,
.checkpoint-card strong {
  display: block;
  overflow-wrap: anywhere;
}

.checkpoint-card span {
  color: var(--snow-muted);
  font-size: 11px;
  font-weight: 900;
  text-transform: uppercase;
}

.checkpoint-card strong {
  margin-top: 5px;
  color: var(--snow-navy);
  font-size: 15px;
}

.checkpoint-card p {
  margin-top: 8px;
  color: #42566c;
  font-size: 13px;
  line-height: 1.42;
}

.checkpoint-card em {
  margin-top: 10px;
  color: #133a5c;
  font-size: 12px;
  font-style: normal;
  font-weight: 850;
  line-height: 1.35;
}

.checkpoint-card code {
  margin-top: 10px;
  padding: 7px;
  font-size: 11px;
  line-height: 1.35;
}

.checkpoint-snow {
  position: relative;
  width: 42px;
  height: 54px;
  align-self: start;
}

.mini-snow-head,
.mini-snow-body {
  position: absolute;
  left: 50%;
  border-radius: 50%;
  background: #ffffff;
  box-shadow:
    inset -4px -5px 0 #d9efff,
    0 0 0 1px rgba(0, 151, 255, 0.16);
  transform: translateX(-50%);
}

.mini-snow-head {
  width: 24px;
  height: 24px;
  top: 2px;
}

.mini-snow-body {
  width: 34px;
  height: 31px;
  bottom: 0;
}

.checkpoint-snow.state-working {
  animation: snow-bob 1.8s ease-in-out infinite;
}

.checkpoint-snow.state-gate .mini-snow-head {
  animation: hat-tap 1.2s ease-in-out infinite;
}

.checkpoint-snow.state-privacy::after {
  content: "";
  position: absolute;
  left: 8px;
  top: 10px;
  width: 26px;
  height: 10px;
  border-radius: 999px;
  background: var(--snow-blue);
}

.checkpoint-snow.state-repair {
  animation: snow-fix 1s ease-in-out infinite;
}

.checkpoint-snow.state-verify::after {
  content: "";
  position: absolute;
  right: -4px;
  top: 20px;
  width: 14px;
  height: 14px;
  border: 3px solid var(--snow-blue);
  border-radius: 50%;
}

.checkpoint-snow.state-detonate {
  animation: snow-melt 2s ease-in-out infinite;
}

.trust-panel,
.run-state-panel {
  min-width: 0;
  margin-top: 18px;
  border: 1px solid rgba(0, 151, 255, 0.14);
  border-radius: 8px;
  padding: 20px;
  background:
    radial-gradient(circle at 92% 8%, rgba(0, 151, 255, 0.18), transparent 24%),
    rgba(255, 255, 255, 0.8);
  box-shadow: 0 22px 52px rgba(0, 21, 42, 0.08);
}

.trust-grid,
.run-state-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.trust-card {
  display: grid;
  grid-template-columns: 42px minmax(0, 1fr);
  gap: 12px;
  min-height: 164px;
  border: 1px solid rgba(17, 22, 21, 0.11);
  border-radius: 8px;
  padding: 12px;
  background: rgba(255, 255, 255, 0.78);
}

.trust-card.passed {
  border-color: rgba(54, 127, 54, 0.28);
  background: #f0fff0;
}

.trust-card.pending,
.trust-card.repairing,
.trust-card.needs_human_gate {
  border-color: rgba(0, 151, 255, 0.22);
}

.trust-card.needs_human_gate {
  background: #f2f8ff;
}

.trust-card.failed {
  border-color: rgba(185, 48, 32, 0.24);
  background: #fff3f0;
}

.trust-card span,
.trust-card strong,
.trust-card p,
.trust-card em {
  display: block;
  overflow-wrap: anywhere;
}

.trust-card span {
  color: var(--snow-muted);
  font-size: 11px;
  font-weight: 900;
  text-transform: uppercase;
}

.trust-card strong {
  margin-top: 5px;
  color: var(--snow-navy);
  font-size: 15px;
}

.trust-card p {
  margin-top: 8px;
  color: #42566c;
  font-size: 13px;
  line-height: 1.42;
}

.trust-card em {
  margin-top: 10px;
  color: #133a5c;
  font-size: 12px;
  font-style: normal;
  font-weight: 850;
  line-height: 1.35;
}

.trust-snow {
  position: relative;
  width: 38px;
  height: 50px;
}

.trust-snow::before,
.trust-snow::after {
  content: "";
  position: absolute;
  left: 50%;
  border-radius: 50%;
  background: #ffffff;
  box-shadow:
    inset -4px -5px 0 #d9efff,
    0 0 0 1px rgba(0, 151, 255, 0.16);
  transform: translateX(-50%);
}

.trust-snow::before {
  width: 23px;
  height: 23px;
  top: 2px;
}

.trust-snow::after {
  width: 33px;
  height: 30px;
  bottom: 0;
}

.trust-snow.state-checking {
  animation: snow-bob 1.6s ease-in-out infinite;
}

.trust-snow.state-passed {
  animation: snow-celebrate 0.9s ease-in-out infinite;
}

.trust-snow.state-passed::before {
  box-shadow:
    inset -4px -5px 0 #d9efff,
    0 0 0 3px rgba(99, 210, 118, 0.24);
}

.trust-snow.state-repairing {
  animation: snow-fix 0.95s ease-in-out infinite;
}

.trust-snow.state-failed {
  animation: hat-tap 0.9s ease-in-out infinite;
}

.timeline,
.artifact-panel {
  min-width: 0;
  padding: 20px;
}

.section-head {
  margin-bottom: 18px;
}

.section-head h2 {
  margin-top: 5px;
  font-size: 24px;
  letter-spacing: 0;
}

.steps,
.artifacts {
  display: grid;
  gap: 10px;
  padding: 0;
  margin: 0;
  list-style: none;
}

.step-card {
  display: grid;
  grid-template-columns: 44px minmax(0, 1fr) auto;
  gap: 14px;
  align-items: center;
  min-height: 74px;
  border: 1px solid rgba(17, 22, 21, 0.11);
  border-radius: 8px;
  padding: 12px;
  background: rgba(255, 255, 255, 0.72);
}

.step-card.running,
.step-card.waiting,
.step-card.failed {
  border-color: rgba(17, 22, 21, 0.34);
  background: #ffffff;
}

.step-number {
  color: #6a736f;
  font-size: 13px;
  font-weight: 900;
}

.step-copy {
  min-width: 0;
}

.step-copy strong,
.step-copy span {
  display: block;
}

.step-copy strong {
  color: #141918;
}

.step-copy span {
  margin-top: 4px;
  color: #55605b;
  font-size: 13px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}

.badge {
  min-width: 86px;
}

.status.running,
.badge.running,
.mini-dot.running {
  background: #cfe7ff;
}

.status.waiting,
.badge.waiting,
.mini-dot.waiting {
  background: #ffe5a3;
}

.status.done,
.badge.done,
.badge.skipped,
.mini-dot.done,
.mini-dot.skipped {
  background: #c9f5bd;
}

.status.failed,
.badge.failed,
.mini-dot.failed {
  background: #ffd2cc;
}

.status.pending,
.badge.pending,
.mini-dot.pending {
  background: #e8ebe8;
}

.artifacts li {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  align-items: center;
  border-bottom: 1px solid rgba(17, 22, 21, 0.12);
  padding: 12px 0;
}

.artifacts strong,
.artifacts code {
  display: block;
}

.artifacts code {
  margin-top: 6px;
}

.artifacts .empty {
  display: block;
  color: #59645f;
  line-height: 1.5;
}

button {
  border-radius: 8px;
  background: #111615;
  color: #f5f3ea;
  cursor: pointer;
}

.artifact-note {
  margin-top: 18px;
  color: #59645f;
  font-size: 13px;
  line-height: 1.5;
}

@media (max-width: 1040px) {
  .overview,
  .workspace,
  .checkpoint-grid,
  .trust-grid,
  .run-state-grid {
    grid-template-columns: 1fr;
  }

  .status-stack {
    justify-content: flex-start;
  }
}

@media (max-width: 720px) {
  .shell {
    padding: 22px 16px;
  }

  .hero,
  .panel-top,
  .section-head {
    display: grid;
  }

  .overview,
  .workspace {
    display: block;
    grid-template-columns: minmax(0, 1fr);
  }

  .progress-panel,
  .focus-panel,
  .timeline,
  .artifact-panel,
  .recovery-panel,
  .trust-panel,
  .run-state-panel {
    width: 100%;
    max-width: 100%;
    margin-bottom: 18px;
  }

  h1 {
    font-size: 31px;
    max-width: 100%;
  }

  code {
    white-space: normal;
    word-break: break-word;
  }

  .stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .stats span {
    min-width: 0;
  }

  .focus-panel h2 {
    font-size: 20px;
    max-width: 100%;
    overflow-wrap: anywhere;
    word-break: break-word;
  }

  .focus-panel p,
  .next-line,
  .next-line strong {
    font-size: 14px;
    max-width: 310px;
    overflow-wrap: anywhere;
    word-break: break-word;
  }

  .snow-scene {
    min-height: 170px;
  }

  .snow-scene::before {
    inset: auto 14px 18px 112px;
  }

  .snowman {
    left: 20px;
    transform: scale(0.9);
    transform-origin: left bottom;
  }

  .snow-prop {
    left: 108px;
    right: 14px;
    bottom: 28px;
    max-width: 218px;
    font-size: 12px;
  }

  .step-card,
  .artifacts li {
    grid-template-columns: 1fr;
  }

  .badge,
  button {
    width: fit-content;
  }
}
"""
