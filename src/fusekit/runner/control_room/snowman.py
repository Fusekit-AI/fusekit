"""Snowman mascot rendering and state selection."""

from __future__ import annotations

import html

from fusekit.runner.job import JobState, JobStep


def render_brand_lockup(surface: str) -> str:
    """Render the SnowmanAI/FuseKit brand lockup."""

    return f"""
        <div class="brand-lockup" aria-label="Snowman AI FuseKit {html.escape(surface)}">
          <span class="brand-mark" aria-hidden="true">
            <span class="mark-hat"></span>
            <span class="mark-head"></span>
            <span class="mark-node mark-node-a"></span>
            <span class="mark-node mark-node-b"></span>
            <span class="mark-node mark-node-c"></span>
          </span>
          <span class="brand-copy">
            <strong>Snowman AI</strong>
            <span>FuseKit {html.escape(surface)}</span>
          </span>
        </div>
"""


def render_snowman_scene(state: str) -> str:
    """Render the animated snowman scene for a launch state."""

    return f"""
        <div class="snow-scene state-{html.escape(state)}" data-snow-scene>
          <div class="snowman" aria-hidden="true">
            <span class="snow-hat"></span>
            <span class="snow-head">
              <span class="eye left"></span>
              <span class="eye right"></span>
              <span class="nose"></span>
              <span class="privacy-mitten left"></span>
              <span class="privacy-mitten right"></span>
            </span>
            <span class="snow-body">
              <span class="button one"></span>
              <span class="button two"></span>
            </span>
            <span class="arm left"></span>
            <span class="arm right"></span>
            <span class="puddle"></span>
            <span class="steam one"></span>
            <span class="steam two"></span>
          </div>
          <div class="snow-prop" data-snow-caption>{html.escape(mascot_caption(state))}</div>
        </div>
"""


def mascot_state(step: JobStep | None, job: JobState) -> str:
    """Choose the snowman animation state for the focused step."""

    if step and step.id == "detonate.workspace":
        return "detonate"
    if job.status == "done":
        return "done"
    if step and _is_privacy_step(step):
        return "privacy"
    if step and step.status == "waiting":
        return "gate"
    if step and step.status == "failed":
        return "repair"
    if step and "verify" in step.id:
        return "verify"
    if step and step.status == "running":
        return "working"
    return "launch"


def mascot_caption(state: str) -> str:
    """Return a short caption for the snowman animation state."""

    captions = {
        "launch": "packing the clean-room suitcase",
        "working": "tightening the little launch bolts",
        "gate": "waiting politely with a tiny access badge",
        "privacy": "covering his eyes while secrets stay private",
        "verify": "checking the live app with a frosty magnifier",
        "repair": "patching the route with a tiny wrench",
        "detonate": "melting away the worker state",
        "done": "celebrating with a snow-safe high five",
    }
    return captions.get(state, captions["launch"])


def _is_privacy_step(step: JobStep) -> bool:
    text = f"{step.id} {step.label} {step.detail}".lower()
    return any(
        marker in text
        for marker in (
            "api key",
            "captcha",
            "credential",
            "hidden prompt",
            "mfa",
            "passphrase",
            "payment",
            "private key",
            "secret",
            "token",
            "vault",
        )
    )
