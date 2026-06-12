from __future__ import annotations

import pytest

from fusekit.detonation.cleanup import DetonationScopeError, detonate


def test_detonate_removes_workspace_paths_and_preserves_survivors(tmp_path) -> None:
    workspace = tmp_path / "app"
    worker = workspace / ".fusekit" / "worker"
    vault = workspace / ".fusekit" / "fusekit.vault.json"
    worker.mkdir(parents=True)
    vault.parent.mkdir(parents=True, exist_ok=True)
    (worker / "scratch.txt").write_text("plaintext", encoding="utf-8")
    vault.write_text("encrypted", encoding="utf-8")

    removed = detonate(
        [worker, vault],
        preserve=[vault],
        workspace_root=workspace,
    )

    assert removed == [str(worker)]
    assert not worker.exists()
    assert vault.read_text(encoding="utf-8") == "encrypted"


def test_detonate_refuses_workspace_root(tmp_path) -> None:
    workspace = tmp_path / "app"
    workspace.mkdir()

    with pytest.raises(DetonationScopeError, match="workspace root"):
        detonate([workspace], workspace_root=workspace)

    assert workspace.exists()


def test_detonate_refuses_symlink_escape(tmp_path) -> None:
    workspace = tmp_path / "app"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    target = outside / "secret.txt"
    target.write_text("do not touch", encoding="utf-8")
    link = workspace / ".fusekit" / "escape"
    link.parent.mkdir()
    link.symlink_to(target)

    with pytest.raises(DetonationScopeError, match="outside workspace root"):
        detonate([link], workspace_root=workspace)

    assert target.read_text(encoding="utf-8") == "do not touch"
