"""Public supervised managed-run proof contract constants."""

from __future__ import annotations

HOSTED_MANAGED_PROOF_BROWSER_STEPS = (
    "Visit the purpose-bound GitHub App install URL.",
    "Sign in and pass GitHub-owned human gates without bypassing MFA, SSO, CAPTCHA, or consent.",
    "Select exactly one repository for the supervised managed-run proof job.",
    "Review the visible FuseKit plan and choose the Managed FuseKit Run lane.",
    "Authorize the displayed Stripe Checkout charge.",
    "Return to the hosted control room and click Start worker after the paid receipt appears.",
)
HOSTED_MANAGED_PROOF_DURABLE_ARTIFACTS = (
    "<job-id>.stripe-webhook-receipt.json",
    "<job-id>.managed-start-response.json",
    "live-checkout-proof.json",
)
HOSTED_MANAGED_PROOF_FORBIDDEN_ACTIONS = (
    (
        "Do not enable public managed runs before live Checkout, webhook, and "
        "worker-dispatch proof pass."
    ),
    "Do not store the short-lived state token or install URL in durable receipts.",
    (
        "Do not paste Stripe keys, webhook secrets, GitHub private keys, OCI "
        "credentials, or provider credentials into public proof."
    ),
    "Do not bypass provider MFA, CAPTCHA, SSO, billing, or consent screens.",
)
