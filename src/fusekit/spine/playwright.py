"""Playwright computer-use spine for provider UI automation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fusekit.errors import ProviderError
from fusekit.spine.openclaw import SpineResult


@dataclass
class PlaywrightBrowserSpine:
    """Visible Playwright browser controller used for supervised setup."""

    profile_dir: Path | None = None
    headless: bool = False
    dry_run: bool = False
    timeout_ms: int = 30_000

    def __post_init__(self) -> None:
        self._playwright: Any | None = None
        self._context: Any | None = None
        self._page: Any | None = None

    def start(self) -> SpineResult:
        """Start a persistent Chromium context."""

        if self.dry_run:
            return SpineResult("start", ("playwright", "chromium", "launch"), "dry-run")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise ProviderError(
                "Playwright is not installed. Run `pip install -e .` or reinstall FuseKit."
            ) from exc
        try:
            self._playwright = sync_playwright().start()
            profile = self.profile_dir or Path.home() / ".fusekit" / "playwright-profile"
            profile.mkdir(parents=True, exist_ok=True)
            self._context = self._playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile),
                headless=self.headless,
            )
            self._context.set_default_timeout(self.timeout_ms)
            self._page = self._context.pages[0] if self._context.pages else self._context.new_page()
        except Exception as exc:
            self.close()
            raise ProviderError(
                "Playwright Chromium is not ready. Run `python -m playwright install chromium` "
                "or use the OCI Cloud Shell/VM lane so FuseKit installs it remotely."
            ) from exc
        return SpineResult("start", ("playwright", "chromium", "launch"), "ok")

    def open(self, url: str) -> SpineResult:
        """Open a URL."""

        if self.dry_run:
            return SpineResult("open", ("playwright", "goto", url), "dry-run")
        page = self._ensure_page()
        page.goto(url, wait_until="domcontentloaded")
        return SpineResult("open", ("playwright", "goto", url), "ok")

    def snapshot(self) -> SpineResult:
        """Capture a sanitized page snapshot without input values or secrets."""

        if self.dry_run:
            return SpineResult("snapshot", ("playwright", "snapshot"), "dry-run")
        page = self._ensure_page()
        payload = page.evaluate(
            """
            () => {
              const visible = (element) => {
                const style = window.getComputedStyle(element);
                const rect = element.getBoundingClientRect();
                return style.visibility !== "hidden"
                  && style.display !== "none"
                  && rect.width > 0
                  && rect.height > 0;
              };
              const labelFor = (element) => {
                if (element.id) {
                  const label = document.querySelector(`label[for="${CSS.escape(element.id)}"]`);
                  if (label && label.textContent) return label.textContent.trim();
                }
                const wrapping = element.closest("label");
                return wrapping && wrapping.textContent ? wrapping.textContent.trim() : "";
              };
              const textOf = (element) =>
                (element.innerText || element.textContent || "")
                  .replace(/\\s+/g, " ")
                  .trim()
                  .slice(0, 160);
              const selector = [
                "button",
                "a[href]",
                "input",
                "textarea",
                "select",
                "[role=button]",
                "[role=link]",
                "[aria-label]",
              ].join(",");
              const elements = Array.from(document.querySelectorAll(selector))
                .filter(visible)
                .slice(0, 80)
                .map((element, index) => ({
                  ref: String(index + 1),
                  tag: element.tagName.toLowerCase(),
                  role: element.getAttribute("role") || "",
                  text: textOf(element),
                  label: labelFor(element),
                  aria: element.getAttribute("aria-label") || "",
                  placeholder: element.getAttribute("placeholder") || "",
                  type: element.getAttribute("type") || "",
                  href: element instanceof HTMLAnchorElement ? element.href : "",
                  disabled: Boolean(
                    element.disabled || element.getAttribute("aria-disabled") === "true"
                  ),
                }));
              return { url: location.href, title: document.title, elements };
            }
            """
        )
        return SpineResult(
            "snapshot",
            ("playwright", "snapshot"),
            "ok",
            stdout=json.dumps(payload, sort_keys=True),
        )

    def click_text(self, text: str) -> SpineResult:
        """Click visible text or a button by accessible name."""

        if self.dry_run:
            return SpineResult("click_text", ("playwright", "click_text", text), "dry-run")
        page = self._ensure_page()
        locator = page.get_by_role("button", name=text).or_(page.get_by_text(text)).first
        locator.click()
        return SpineResult("click_text", ("playwright", "click_text", text), "ok")

    def fill_label(self, label: str, value: str) -> SpineResult:
        """Fill an input by label/placeholder without logging the value."""

        if self.dry_run:
            return SpineResult("fill_label", ("playwright", "fill_label", label), "dry-run")
        page = self._ensure_page()
        page.get_by_label(label).or_(page.get_by_placeholder(label)).first.fill(value)
        return SpineResult("fill_label", ("playwright", "fill_label", label), "ok")

    def press(self, key: str) -> SpineResult:
        """Press a keyboard key."""

        if self.dry_run:
            return SpineResult("press", ("playwright", "press", key), "dry-run")
        self._ensure_page().keyboard.press(key)
        return SpineResult("press", ("playwright", "press", key), "ok")

    def wait_for_text(self, text: str) -> SpineResult:
        """Wait for visible text."""

        if self.dry_run:
            return SpineResult("wait_for_text", ("playwright", "wait_for_text", text), "dry-run")
        self._ensure_page().get_by_text(text).first.wait_for()
        return SpineResult("wait_for_text", ("playwright", "wait_for_text", text), "ok")

    def clipboard_text(self) -> str:
        """Read clipboard text from the browser context."""

        if self.dry_run:
            return ""
        page = self._ensure_page()
        value = page.evaluate("navigator.clipboard.readText()")
        return str(value)

    def close(self) -> None:
        """Close the browser context."""

        if self._context is not None:
            self._context.close()
            self._context = None
        if self._playwright is not None:
            self._playwright.stop()
            self._playwright = None

    def _ensure_page(self) -> Any:
        if self._page is None:
            self.start()
        return self._page
