"""Automation spine integrations."""

from fusekit.spine.infer import (
    InferredUiAction,
    OpenAiUiNavigator,
    StaticUiNavigator,
    StumpClassification,
    classify_ui_stump,
    run_inferred_navigation,
)
from fusekit.spine.openclaw import OpenClawBrowserSpine
from fusekit.spine.playbooks import (
    BrowserPlaybookEvent,
    provider_authorization_playbook,
    provider_handoff_playbook,
)
from fusekit.spine.playwright import PlaywrightBrowserSpine
from fusekit.spine.ui_playbooks import execute_provider_ui_playbook, provider_ui_playbook

__all__ = [
    "BrowserPlaybookEvent",
    "InferredUiAction",
    "OpenClawBrowserSpine",
    "OpenAiUiNavigator",
    "PlaywrightBrowserSpine",
    "StaticUiNavigator",
    "StumpClassification",
    "classify_ui_stump",
    "execute_provider_ui_playbook",
    "provider_authorization_playbook",
    "provider_handoff_playbook",
    "provider_ui_playbook",
    "run_inferred_navigation",
]
