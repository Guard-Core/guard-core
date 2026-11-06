from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_RUNTIME_EXTRAS = ("redis", "geo", "cloud")


def test_readme_says_how_to_get_each_runtime_extra_and_pins_the_adapter_floor() -> None:
    readme = (_ROOT / "README.md").read_text()
    pyproject = (_ROOT / "pyproject.toml").read_text()
    for extra in _RUNTIME_EXTRAS:
        assert f"\n{extra} = [" in pyproject
        assert f"`guard-core[{extra}]`" in readme
    assert '"guard-core>=5.0.0,<6"' in readme
