from guard_core.sync._utils.detection_scan import _scan_request_scope
from guard_core.sync._utils.route_gate import route_template_event_fields


def scanned_request_route_template_fields() -> dict[str, str]:
    event_request = _scan_request_scope.get()[1]
    if event_request is None:
        return {}
    return route_template_event_fields(event_request[0].state)
