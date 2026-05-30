from fusekit import __version__


def test_version_is_available() -> None:
    assert __version__ == "0.1.0"
