import json
from collections.abc import Callable, Iterable
from functools import partial

from guard_core.sync.handlers._suspatterns_xml_xxe import (
    _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE,
    _xml_internal_entity_finditer,
    _xml_system_finditer,
    _xml_xxe_public_external_dtd_finditer,
)
from tests.host_load_factor import minimum_normalized


def _listed(
    finder: Callable[..., Iterable[object]], *arguments: object
) -> list[object]:
    return list(finder(*arguments))


_SIZES = (16384, 32768, 65536, 131072)
_ROUNDS = 9


def _url_shapes(size: int) -> dict[str, str]:
    return {
        "public_in_url": '<!DOCTYPE x PUBLIC "id" "http://evil/'
        + "PUBLIC " * (size // 7)
        + '">',
        "public_in_trailer": '<!DOCTYPE x PUBLIC "id" "http://evil/x" '
        + "PUBLIC " * (size // 7)
        + ">",
        "empty_scheme_decoys": '<!DOCTYPE x PUBLIC "id" '
        + '"http://" ' * (size // 10)
        + '"http://evil/x">',
    }


def _checked(
    finder: Callable[..., Iterable[object]],
    expect_match: bool,
    label: str,
    *arguments: object,
) -> None:
    assert bool(_listed(finder, *arguments)) is expect_match, label


def measure() -> dict[str, list[float]]:
    result: dict[str, list[float]] = {}
    compiled = _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE
    urls = {size: _url_shapes(size) for size in _SIZES}
    for shape in urls[_SIZES[0]]:
        for size in _SIZES:
            _checked(
                _xml_xxe_public_external_dtd_finditer,
                True,
                shape,
                urls[size][shape],
                compiled,
            )
        result[shape] = minimum_normalized(
            [
                partial(
                    _listed,
                    _xml_xxe_public_external_dtd_finditer,
                    urls[size][shape],
                    compiled,
                )
                for size in _SIZES
            ],
            _ROUNDS,
        )
    for label, finder, tail in [
        ("system_openers", _xml_system_finditer, ">"),
        ("internal_openers", _xml_internal_entity_finditer, "<!ENTITY"),
    ]:
        texts = {size: "<!DOCTYPE" * (size // 9) + tail for size in _SIZES}
        for size in _SIZES:
            _checked(finder, False, label, texts[size])
        result[label] = minimum_normalized(
            [partial(_listed, finder, texts[size]) for size in _SIZES], _ROUNDS
        )
    return result


if __name__ == "__main__":
    print(json.dumps(measure()))
