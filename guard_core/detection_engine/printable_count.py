_NON_PRINTABLE_ASCII = bytes([*range(0x20), 0x7F])


def printable_count(text: str) -> int:
    """How many characters of ``text`` are printable, the count of
    ``sum(map(str.isprintable, text))``. A text that is all ASCII (a decoded block
    of zeros, say) is counted by deleting the non-printable bytes, in C, instead
    of one Python call per character."""
    if text.isprintable():
        return len(text)
    if text.isascii():
        return len(text.encode("ascii").translate(None, _NON_PRINTABLE_ASCII))
    return sum(map(str.isprintable, text))
