from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig


class CallableRoute:
    def __call__(self, item: int) -> str:
        return str(item)


def test_a_callable_object_is_decorated_under_its_class_name() -> None:
    guard = SecurityDecorator(SecurityConfig(enable_redis=False))

    first = guard.rate_limit(5, 60)(CallableRoute())
    second = guard.rate_limit(7, 60)(CallableRoute())

    first_id = f"{__name__}.CallableRoute"
    assert first(1) == "1"
    assert guard.get_route_config(first_id) is not None
    assert guard.get_route_config(f"{first_id}#2") is not None
    assert second(2) == "2"
