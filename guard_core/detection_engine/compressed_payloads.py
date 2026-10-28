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
    """Inflate a gzip or zlib stream into at most ``max_output_bytes`` bytes,
    and no more than ``MAX_DECOMPRESSION_RATIO`` times the compressed size
    (with a small floor). Returns ``None`` when ``raw`` is not such a stream;
    otherwise the inflated bytes and whether the output was cut short by the
    bound (a decompression bomb), so the caller can report an incomplete scan."""
    if looks_like_gzip(raw):
        wbits = _GZIP_WBITS
    elif looks_like_zlib(raw):
        wbits = zlib.MAX_WBITS
    else:
        return None
    limit = min(
        max_output_bytes,
        max(MIN_DECOMPRESSED_ALLOWANCE_BYTES, MAX_DECOMPRESSION_RATIO * len(raw)),
    )
    decompressor = zlib.decompressobj(wbits)
    try:
        inflated = decompressor.decompress(raw, limit)
    except zlib.error:
        return None
    return inflated, len(inflated) >= limit and not decompressor.eof
