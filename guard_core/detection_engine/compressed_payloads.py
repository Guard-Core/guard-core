import zlib

GZIP_MAGIC = b"\x1f\x8b"
MAX_DECOMPRESSION_RATIO = 100
MIN_DECOMPRESSED_ALLOWANCE_BYTES = 16384
_GZIP_WBITS = 16 + zlib.MAX_WBITS
_ZLIB_CMF = 0x78


def looks_like_zlib(raw: bytes) -> bool:
    return len(raw) >= 2 and raw[0] == _ZLIB_CMF and (raw[0] * 256 + raw[1]) % 31 == 0


def looks_like_gzip(raw: bytes) -> bool:
    return raw[:2] == GZIP_MAGIC


def bounded_inflate(raw: bytes, max_output_bytes: int) -> tuple[bytes, bool] | None:
    """Inflate a gzip or zlib stream into at most ``max_output_bytes`` bytes; the
    cap alone bounds memory and time, and no ratio or floor stops it earlier.
    Returns ``None`` when ``raw`` is not such a stream; otherwise the inflated
    bytes and whether the cap cut them short, which the caller turns into the
    outcome a plain body past the cap takes, never a pattern threat."""
    if looks_like_gzip(raw):
        wbits = _GZIP_WBITS
    elif looks_like_zlib(raw):
        wbits = zlib.MAX_WBITS
    else:
        return None
    decompressor = zlib.decompressobj(wbits)
    try:
        inflated = decompressor.decompress(raw, max_output_bytes)
    except zlib.error:
        return None
    return inflated, len(inflated) >= max_output_bytes and not decompressor.eof


def is_likely_decompression_bomb(compressed_size: int, unpacked_size: int) -> bool:
    """Only words the refusal detail; it never changes a verdict."""
    return (
        unpacked_size > MIN_DECOMPRESSED_ALLOWANCE_BYTES
        and unpacked_size > MAX_DECOMPRESSION_RATIO * compressed_size
    )
