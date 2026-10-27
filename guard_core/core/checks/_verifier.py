import inspect


async def resolve_verifier_result(value: object) -> object:
    if inspect.isawaitable(value):
        resolved: object = await value
        return resolved
    return value
