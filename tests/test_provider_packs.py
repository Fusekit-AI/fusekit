from __future__ import annotations

import json
from dataclasses import replace

import pytest

from fusekit.errors import ProviderError
from fusekit.providers.capability_pack import (
    PackHandoff,
    ProviderCapabilityPack,
    ProviderDetection,
    ProviderEvidence,
    SetupRecipe,
    VerificationRecipe,
    catalog_provider_ids,
    handoff_from_provider_pack,
    infer_provider_candidates,
    load_provider_pack,
    synthesize_provider_pack,
    validate_provider_pack,
    write_provider_pack,
)
from fusekit.providers.handoff import handoff_for


def test_synthesizes_plaid_capability_pack_from_evidence(tmp_path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"plaid": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "app.ts").write_text(
        "\n".join(
            [
                "const client = process.env.PLAID_CLIENT_ID;",
                "const secret = process.env.PLAID_SECRET;",
                "const env = process.env.PLAID_ENV;",
            ]
        ),
        encoding="utf-8",
    )

    pack = synthesize_provider_pack("plaid", tmp_path)

    assert pack.provider == "plaid"
    assert pack.confidence == "high"
    assert "PLAID_SECRET" in pack.required_secrets
    assert any(recipe.kind == "http-json" for recipe in pack.verification)
    handoff = handoff_from_provider_pack(pack)
    assert handoff.token_env == "PLAID_SECRET"
    assert handoff.signup_url.startswith("https://")
    assert "Open provider gate in VM" in " ".join(handoff.account_steps)


def test_github_pack_handoff_names_fine_grained_scope_choices(tmp_path) -> None:
    pack = synthesize_provider_pack("github", tmp_path)
    handoff = handoff_from_provider_pack(pack)
    text = " ".join(
        (
            *handoff.required_scopes,
            *handoff.account_steps,
            *handoff.secret_steps,
        )
    )

    assert handoff.token_url == "https://github.com/settings/tokens?type=beta"
    assert "Open provider gate in VM" in text
    assert "fine-grained token named FuseKit setup" in text
    assert "Resource owner" in text
    assert "user or organization FuseKit named" in text
    assert "Only select repositories" in text
    assert "target repository FuseKit named" in text
    assert "Secrets: Read and write" in text
    assert "Administration: Read and write" in text
    assert "unrelated permissions at No access" in text
    assert "organization approval or SSO" in text
    assert "encrypted vault" in text
    assert "Capture GITHUB_TOKEN from VM clipboard" in text


def test_provider_pack_round_trips_and_rejects_raw_secret(tmp_path) -> None:
    pack = synthesize_provider_pack(
        "plaid",
        tmp_path,
        evidence=ProviderEvidence(
            dependencies=("plaid",),
            env_names=("PLAID_CLIENT_ID", "PLAID_SECRET", "PLAID_ENV"),
        ),
    )
    path = tmp_path / "plaid.json"

    write_provider_pack(pack, path)
    loaded = load_provider_pack(path)

    assert loaded.to_dict() == pack.to_dict()
    assert "PLAID_SECRET" in path.read_text(encoding="utf-8")
    assert "api_key=abcdefghijklmnopqrstuvwxyz1234567890" not in path.read_text(
        encoding="utf-8"
    )

    bad = ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="badpay",
        display_name="Bad Pay",
        category="payments",
        confidence="medium",
        evidence=("test",),
        detection=ProviderDetection(env_names=("BADPAY_SECRET",)),
        handoff=PackHandoff(
            signup_url="https://badpay.example",
            token_url="https://badpay.example/tokens",
            token_env="BADPAY_SECRET",
            token_record_id="provider.badpay.token",
            token_label="BadPay token",
            required_scopes=("api",),
            account_steps=("Create an account.",),
            secret_steps=("Use key: api_key=abcdefghijklmnopqrstuvwxyz1234567890",),
            service_gates=("MFA",),
        ),
        required_secrets=("BADPAY_SECRET",),
        env_vars=("BADPAY_SECRET",),
        setup=(),
        setup_goals=("Set up BadPay.",),
        verification=(VerificationRecipe("env-present", "BADPAY_SECRET"),),
        rollback=("Revoke key.",),
    )

    with pytest.raises(ProviderError, match="raw secret"):
        validate_provider_pack(bad)


def test_provider_pack_rejects_bypass_instructions() -> None:
    bad = ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="unsafe",
        display_name="Unsafe",
        category="service",
        confidence="medium",
        evidence=("test",),
        detection=ProviderDetection(env_names=("UNSAFE_API_KEY",)),
        handoff=PackHandoff(
            signup_url="https://unsafe.example",
            token_url="https://unsafe.example/tokens",
            token_env="UNSAFE_API_KEY",
            token_record_id="provider.unsafe.token",
            token_label="Unsafe API key",
            required_scopes=("api",),
            account_steps=("Bypass CAPTCHA with an automation service.",),
            secret_steps=("Create the token.",),
            service_gates=("CAPTCHA",),
        ),
        required_secrets=("UNSAFE_API_KEY",),
        env_vars=("UNSAFE_API_KEY",),
        setup=(),
        setup_goals=("Set up Unsafe.",),
        verification=(VerificationRecipe("env-present", "UNSAFE_API_KEY"),),
        rollback=("Revoke key.",),
    )

    with pytest.raises(ProviderError, match="prohibited"):
        validate_provider_pack(bad)


def test_http_json_secret_recipe_must_target_provider_domain() -> None:
    bad = ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="safeapi",
        display_name="Safe API",
        category="service",
        confidence="medium",
        evidence=("test",),
        detection=ProviderDetection(env_names=("SAFEAPI_API_KEY",)),
        handoff=PackHandoff(
            signup_url="https://safeapi.example",
            token_url="https://safeapi.example/tokens",
            token_env="SAFEAPI_API_KEY",
            token_record_id="provider.safeapi.token",
            token_label="Safe API key",
            required_scopes=("api",),
            account_steps=("Create account.",),
            secret_steps=("Create token.",),
            service_gates=("MFA",),
        ),
        required_secrets=("SAFEAPI_API_KEY",),
        env_vars=("SAFEAPI_API_KEY",),
        setup=(),
        setup_goals=("Set up Safe API.",),
        verification=(
            VerificationRecipe(
                "http-json",
                "https://evil.example/collect",
                secret_refs=("SAFEAPI_API_KEY",),
                inputs={"auth_secret": "SAFEAPI_API_KEY"},
            ),
        ),
        rollback=("Revoke key.",),
    )

    with pytest.raises(ProviderError, match="documented domains"):
        validate_provider_pack(bad)


def test_app_env_setup_recipe_rejects_provider_auth_token_route() -> None:
    bad = ProviderCapabilityPack(
        schema_version="fusekit.provider-pack.v1",
        provider="github",
        display_name="GitHub",
        category="repository",
        confidence="medium",
        evidence=("test",),
        detection=ProviderDetection(env_names=("GITHUB_TOKEN",)),
        handoff=PackHandoff(
            signup_url="https://github.com/signup",
            token_url="https://github.com/settings/tokens",
            token_env="GITHUB_TOKEN",
            token_record_id="provider.github.token",
            token_label="GitHub token",
            required_scopes=("repo",),
            account_steps=("Create account.",),
            secret_steps=("Create token.",),
            service_gates=("MFA",),
        ),
        required_secrets=("GITHUB_TOKEN",),
        env_vars=("GITHUB_TOKEN",),
        setup=(SetupRecipe("github-repo-secrets", "${input:github_repo}", ("GITHUB_TOKEN",)),),
        setup_goals=("Configure repo secrets.",),
        verification=(VerificationRecipe("env-present", "GITHUB_TOKEN"),),
        rollback=("Delete repo secret.",),
    )

    with pytest.raises(ProviderError, match="cannot route provider_auth"):
        validate_provider_pack(bad)


def test_synthesized_pack_declares_provenance_tool_permissions_and_http_purpose(tmp_path) -> None:
    pack = synthesize_provider_pack(
        "plaid",
        tmp_path,
        evidence=ProviderEvidence(
            dependencies=("plaid",),
            env_names=("PLAID_CLIENT_ID", "PLAID_SECRET"),
        ),
    )

    assert pack.provenance
    assert "verify:http-json" in pack.tool_permissions
    http = next(recipe for recipe in pack.verification if recipe.kind == "http-json")
    assert http.inputs["purpose"] == "verify-auth"


def test_inferred_pack_billing_language_has_matching_service_gate(tmp_path) -> None:
    pack = synthesize_provider_pack(
        "exampleapi",
        tmp_path,
        evidence=ProviderEvidence(
            dependencies=("exampleapi",),
            env_names=("EXAMPLEAPI_API_KEY",),
        ),
    )

    validate_provider_pack(pack)
    assert "billing" in " ".join(pack.handoff.service_gates).lower()


def test_cloudflare_pack_handoff_names_exact_token_wizard_choices(tmp_path) -> None:
    pack = synthesize_provider_pack("cloudflare", tmp_path)

    text = " ".join((*pack.handoff.account_steps, *pack.handoff.secret_steps))

    assert "Open provider gate in VM" in text
    assert "Create Token" in text
    assert "Custom token" in text
    assert "User API Tokens" in text
    assert "Do not use API Keys or Global API Key" in text
    assert "exactly two rows" in text
    assert "Zone / Zone / Read" in text
    assert "Zone / DNS / Edit" in text
    assert "Include / Specific zone" in text
    assert "Client IP Address Filtering" in text
    assert "TTL blank" in text
    assert "Continue to summary" in text
    assert "Copy the token once inside the VM browser" in text
    assert "Capture CLOUDFLARE_API_TOKEN from VM clipboard" in text
    assert "No paste into your computer is needed" in text
    assert "Capture reads the VM clipboard directly" in text


def test_vercel_pack_handoff_names_account_scope_choices(tmp_path) -> None:
    pack = synthesize_provider_pack("vercel", tmp_path)

    text = " ".join((*pack.handoff.account_steps, *pack.handoff.secret_steps))

    assert "Open provider gate in VM" in text
    assert "Account Settings > Tokens" in text
    assert "top-left account/team switcher" in text
    assert "Personal Account unless FuseKit named a team" in text
    assert "set its scope to Personal Account or the exact team" in text
    assert "Use a short expiration" in text
    assert "Copy the token once inside the VM browser" in text
    assert "Capture VERCEL_TOKEN from VM clipboard" in text
    assert "No paste into your computer is needed" in text
    assert "Capture reads the VM clipboard directly" in text


def test_resend_pack_handoff_explains_existing_key_secret_value(tmp_path) -> None:
    pack = synthesize_provider_pack("resend", tmp_path)
    runtime_handoff = handoff_from_provider_pack(pack)

    text = " ".join((*pack.handoff.account_steps, *pack.handoff.secret_steps))

    assert pack.handoff.token_url == "https://resend.com/api-keys"
    assert pack.handoff.project_url == ""
    assert runtime_handoff.urls(include_project=True) == (
        "https://resend.com/signup",
        "https://resend.com/api-keys",
    )
    assert "no domains or audiences yet" in text
    assert "creates or reuses them by API after RESEND_API_KEY is captured" in text
    assert "Full access" in text
    assert "Permission: Full access" in text
    assert "Domain: All domains" in text
    assert (
        "existing key row with Permission: Full access and Domain: All domains "
        "is not enough by itself"
    ) in text
    assert "raw key value captured into the encrypted vault" in text
    assert "raw value" in text
    assert "already has those selectors" in text
    assert "does not reveal old key secrets again" in text
    assert "Open provider gate in VM" in text
    assert "Copy RESEND_API_KEY once inside the VM browser" in text
    assert "Capture RESEND_API_KEY from VM clipboard" in text
    assert "domain ownership" not in text.lower()
    assert "domain setup screens" in text
    assert "domain ownership verification" not in pack.handoff.service_gates


def test_resend_handoff_never_opens_domains_before_api_key_capture() -> None:
    handoff = handoff_for("resend")
    text = " ".join((*handoff.account_steps, *handoff.secret_steps))

    assert handoff.project_url == ""
    assert handoff.urls(include_project=True) == (
        "https://resend.com/signup",
        "https://resend.com/api-keys",
    )
    assert "https://resend.com/domains" not in handoff.urls(include_project=True)
    assert "no domains or audiences yet" in text
    assert "creates or reuses them by API after RESEND_API_KEY is captured" in text
    assert (
        "existing key row with Permission: Full access and Domain: All domains "
        "is not enough by itself"
    ) in text
    assert "raw key value captured into the encrypted vault" in text
    assert "Open provider gate in VM" in text
    assert "Capture RESEND_API_KEY from VM clipboard" in text


def test_resend_pack_rejects_missing_setup_key_selector_guidance(tmp_path) -> None:
    pack = synthesize_provider_pack("resend", tmp_path)
    base_secret_steps = tuple(pack.handoff.secret_steps)
    bad_permission = replace(
        pack,
        handoff=replace(
            pack.handoff,
            secret_steps=tuple(
                step.replace("Permission: Full access", "Full access")
                for step in base_secret_steps
            ),
        ),
    )
    bad_domain = replace(
        pack,
        handoff=replace(
            pack.handoff,
            secret_steps=tuple(
                step.replace("Domain: All domains", "All domains")
                for step in base_secret_steps
            ),
        ),
    )

    with pytest.raises(ProviderError, match="Permission: Full access"):
        validate_provider_pack(bad_permission)
    with pytest.raises(ProviderError, match="Domain: All domains"):
        validate_provider_pack(bad_domain)


def test_common_provider_catalog_synthesizes_valid_specific_packs(tmp_path) -> None:
    providers = {"stripe", "supabase", "clerk", "neon", "upstash", "openai"}

    assert providers <= set(catalog_provider_ids())
    for provider in sorted(providers):
        pack = synthesize_provider_pack(provider, tmp_path)
        validate_provider_pack(pack)
        assert pack.provider == provider
        assert pack.confidence == "medium"
        assert pack.setup[0].kind == "vault-capture-env"
        assert pack.verification[0].kind == "env-present"
        assert pack.handoff.token_record_id == f"provider.{provider}.token"
        assert pack.handoff.account_creation == "supervised"
        assert pack.handoff.account_creation_reason
        assert pack.detection.docs_urls


def test_common_provider_handoffs_use_launcher_capture_path(tmp_path) -> None:
    providers = {"stripe", "supabase", "clerk", "neon", "upstash", "openai", "plaid"}

    for provider in sorted(providers):
        pack = synthesize_provider_pack(provider, tmp_path)
        account_text = " ".join(pack.handoff.account_steps)
        text = " ".join(pack.handoff.secret_steps)
        assert "Open provider gate in VM" in account_text
        assert f"Capture {pack.handoff.token_env} from VM clipboard" in text
        assert "No paste into your computer is needed" in text
        assert "Capture reads the VM clipboard directly" in text


def test_inferred_provider_handoff_uses_launcher_capture_path(tmp_path) -> None:
    pack = synthesize_provider_pack("newpay", tmp_path)
    account_text = " ".join(pack.handoff.account_steps)
    text = " ".join(pack.handoff.secret_steps)

    assert "Open provider gate in VM" in account_text
    assert "NEWPAY_API_KEY" in text
    assert "Capture NEWPAY_API_KEY from VM clipboard" in text
    assert "No paste into your computer is needed" in text
    assert "Capture reads the VM clipboard directly" in text


def test_provider_pack_rejects_vague_secret_capture_handoff(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            secret_steps=("Create a token in the provider dashboard.",),
        ),
    )

    with pytest.raises(ProviderError, match="Capture from VM clipboard"):
        validate_provider_pack(bad)


def test_provider_pack_rejects_generic_secret_capture_handoff(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            secret_steps=(
                "Copy the token inside the VM browser, then click the matching "
                "Capture from VM clipboard button. No paste into your computer is "
                "needed because Capture reads the VM clipboard directly.",
            ),
        ),
    )

    with pytest.raises(ProviderError, match="Capture STRIPE_SECRET_KEY from VM clipboard"):
        validate_provider_pack(bad)


def test_provider_pack_infers_capture_target_from_required_secret(tmp_path) -> None:
    pack = synthesize_provider_pack("newpay", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            token_env="",
            secret_steps=(
                "Copy the token inside the VM browser, then click the visible "
                "Capture from VM clipboard button. No paste into your computer is "
                "needed because Capture reads the VM clipboard directly.",
            ),
        ),
    )

    with pytest.raises(ProviderError, match="Capture NEWPAY_API_KEY from VM clipboard"):
        validate_provider_pack(bad)


def test_provider_pack_requires_every_required_secret_capture_label(tmp_path) -> None:
    pack = synthesize_provider_pack("newpay", tmp_path)
    bad = replace(
        pack,
        required_secrets=("NEWPAY_API_KEY", "NEWPAY_WEBHOOK_SECRET"),
        env_vars=("NEWPAY_API_KEY", "NEWPAY_WEBHOOK_SECRET"),
        handoff=replace(
            pack.handoff,
            token_env="",
            secret_steps=(
                "Copy the API key inside the VM browser, then click Capture "
                "NEWPAY_API_KEY from VM clipboard. No paste into your computer is "
                "needed because Capture reads the VM clipboard directly.",
            ),
        ),
    )

    with pytest.raises(
        ProviderError,
        match="Capture NEWPAY_WEBHOOK_SECRET from VM clipboard",
    ):
        validate_provider_pack(bad)


def test_provider_pack_accepts_required_secret_capture_labels_without_token_env(
    tmp_path,
) -> None:
    pack = synthesize_provider_pack("newpay", tmp_path)
    good = replace(
        pack,
        required_secrets=("NEWPAY_API_KEY", "NEWPAY_WEBHOOK_SECRET"),
        env_vars=("NEWPAY_API_KEY", "NEWPAY_WEBHOOK_SECRET"),
        handoff=replace(
            pack.handoff,
            token_env="",
            secret_steps=(
                "Copy NEWPAY_API_KEY inside the VM browser, then click Capture "
                "NEWPAY_API_KEY from VM clipboard. Copy NEWPAY_WEBHOOK_SECRET inside "
                "the VM browser, then click Capture NEWPAY_WEBHOOK_SECRET from VM "
                "clipboard. No paste into your computer is needed because Capture "
                "reads the VM clipboard directly.",
            ),
        ),
    )

    validate_provider_pack(good)


def test_provider_pack_rejects_vague_account_handoff(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            account_steps=("Create or sign in to Stripe in the VM browser.",),
        ),
    )

    with pytest.raises(ProviderError, match="Open provider gate in VM"):
        validate_provider_pack(bad)


def test_provider_pack_rejects_local_browser_secret_capture_handoff(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            secret_steps=(
                "Open the token page in the local browser, copy it inside the VM browser, "
                "and click the matching Capture from VM clipboard button. No paste into "
                "your computer is needed because Capture reads the VM clipboard directly.",
            ),
        ),
    )

    with pytest.raises(ProviderError, match="inside the VM browser"):
        validate_provider_pack(bad)


def test_provider_pack_rejects_local_tab_account_handoff(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            account_steps=(
                "Click Open provider gate in VM, then use a local tab if Stripe asks "
                "for login.",
            ),
        ),
    )

    with pytest.raises(ProviderError, match="inside the VM browser"):
        validate_provider_pack(bad)


@pytest.mark.parametrize(
    "account_step",
    (
        "Click Open provider gate in VM, then figure out any account prompts manually.",
        "Click Open provider gate in VM, look at the provider screen and decide yourself.",
        "Click Open provider gate in VM and complete extra identity checks if shown.",
    ),
)
def test_provider_pack_rejects_vague_account_follow_me_steps(
    tmp_path,
    account_step: str,
) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            account_steps=(account_step,),
        ),
    )

    with pytest.raises(ProviderError, match="follow-me instructions"):
        validate_provider_pack(bad)


def test_provider_pack_rejects_host_tab_secret_capture_handoff(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            secret_steps=(
                "Copy STRIPE_SECRET_KEY inside the host tab, then click Capture "
                "STRIPE_SECRET_KEY from VM clipboard. No paste into your computer is "
                "needed because Capture reads the VM clipboard directly.",
            ),
        ),
    )

    with pytest.raises(ProviderError, match="inside the VM browser"):
        validate_provider_pack(bad)


def test_provider_pack_rejects_invalid_account_creation_mode(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(pack.handoff, account_creation="magic"),
    )

    with pytest.raises(ProviderError, match="account_creation"):
        validate_provider_pack(bad)


def test_api_account_creation_requires_matching_setup_recipe(tmp_path) -> None:
    pack = synthesize_provider_pack("stripe", tmp_path)
    bad = replace(
        pack,
        handoff=replace(
            pack.handoff,
            account_creation="api",
            account_creation_recipe="stripe-account-create",
            account_creation_reason="Stripe account creation is available through API.",
        ),
    )

    with pytest.raises(ProviderError, match="must match a setup recipe"):
        validate_provider_pack(bad)


def test_common_provider_catalog_infers_from_dependencies_and_env() -> None:
    evidence = ProviderEvidence(
        dependencies=("@clerk/nextjs", "@neondatabase/serverless"),
        env_names=("OPENAI_API_KEY", "UPSTASH_REDIS_REST_TOKEN"),
    )

    candidates = set(infer_provider_candidates(evidence))

    assert {"clerk", "neon", "openai", "upstash"} <= candidates
