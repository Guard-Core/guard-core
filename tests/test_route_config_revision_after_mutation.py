import pytest

from guard_core.decorators.route_config import (
    RouteConfigRevision,
    _TrackedDict,
    _TrackedList,
    _TrackedSet,
)


class _Probe(RouteConfigRevision):
    """Records what the container holds at the moment the revision moves."""

    def __init__(self) -> None:
        super().__init__()
        self.container: list[object] | dict[str, object] | set[object] = []
        self.sizes: list[int] = []

    def bump(self) -> None:
        super().bump()
        self.sizes.append(len(self.container))


def test_a_list_edit_moves_the_revision_after_the_change() -> None:
    probe = _Probe()
    tracked = _TrackedList(revision=probe)
    probe.container = tracked

    tracked.append(1)
    tracked.extend([2, 3])

    assert probe.sizes == [1, 3]


def test_a_dict_edit_moves_the_revision_after_the_change() -> None:
    probe = _Probe()
    tracked = _TrackedDict(revision=probe)
    probe.container = tracked

    tracked["a"] = 1
    tracked.update({"b": 2})

    assert probe.sizes == [1, 2]


def test_a_set_edit_moves_the_revision_after_the_change() -> None:
    probe = _Probe()
    tracked = _TrackedSet(revision=probe)
    probe.container = tracked

    tracked.add(1)
    tracked.update({2, 3})

    assert probe.sizes == [1, 3]


def test_a_slice_assignment_moves_the_revision_after_the_change() -> None:
    probe = _Probe()
    tracked = _TrackedList([1, 2, 3], revision=probe)
    probe.container = tracked

    tracked[0:3] = [9]

    assert probe.sizes == [1]


def test_a_mutation_that_raises_still_moves_the_revision_once() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedList(revision=revision)

    with pytest.raises(ValueError):
        tracked.remove(1)

    assert revision.value == 1
