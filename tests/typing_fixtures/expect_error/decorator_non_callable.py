from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig

guard = SecurityDecorator(SecurityConfig())

guard.rate_limit(5, 60)(42)
