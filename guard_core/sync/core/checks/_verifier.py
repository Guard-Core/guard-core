import inspect


def resolve_verifier_result(value: object) -> object:
    if inspect.isawaitable(value):
        raise TypeError(
            "async verifier not supported in sync (WSGI) deployments; "
            "supply a sync verifier"
        )
    return value
