import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

ATTACK = "<script>alert(1)</script>"


class _FirstValueRequest(MockGuardRequest):
    """A request whose query_params keeps one value per name, the way Tornado's
    adapter and Flask's .args do, while url_full keeps the whole query string."""

    def __init__(self, query: str, keep: str = "last") -> None:
        super().__init__(path=f"/s?{query}")
        pairs = [pair.split("=", 1) for pair in query.split("&") if "=" in pair]
        chosen: dict[str, str] = {}
        for name, value in pairs:
            if keep == "first":
                chosen.setdefault(name, value)
            else:
                chosen[name] = value
        self._query_params = chosen
        self._url_path = "/s"

    @property
    def url_path(self) -> str:
        return self._url_path


@pytest.mark.parametrize("keep", ["first", "last"])
@pytest.mark.parametrize(
    "query",
    [
        f"q={ATTACK}&q=x",
        f"q=x&q={ATTACK}",
        f"q=a&q={ATTACK}&q=b",
        "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&q=x",
        "q=x&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "q=x&q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&other=1",
    ],
)
async def test_every_repeated_value_is_scanned(query: str, keep: str) -> None:
    request = _FirstValueRequest(query, keep=keep)

    result = await detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is True
    assert "xss" in result.threat_categories


async def test_a_plus_sign_in_a_repeated_value_decodes_to_a_space() -> None:
    request = _FirstValueRequest("q=x&q=union+select+password+from+users", keep="first")

    result = await detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is True


@pytest.mark.parametrize(
    "query",
    [
        "tag=a&tag=b&tag=c",
        "a=&a=&b=",
        "q=red+shoes&q=blue+boots",
        "page=1&page=2",
    ],
)
async def test_benign_repeated_values_stay_clean(query: str) -> None:
    request = _FirstValueRequest(query)

    result = await detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is False


async def test_an_excluded_param_name_excludes_its_repeats_too() -> None:
    request = _FirstValueRequest(f"q=x&q={ATTACK}", keep="first")
    config = SecurityConfig(excluded_detection_params={"q"})

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is False


async def test_a_request_without_a_full_url_still_scans_its_params() -> None:
    class _Bare(MockGuardRequest):
        @property
        def url_full(self) -> str:
            raise AttributeError("url_full")

    request = _Bare(path="/s", query_params={"q": ATTACK})

    result = await detect_penetration_attempt(request, SecurityConfig())

    assert result.is_threat is True
