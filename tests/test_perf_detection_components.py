from perf_gate import detection_components as components


def test_benign_text_is_cut_to_the_requested_size() -> None:
    assert len(components.benign_text(200)) == 200
    assert len(components.benign_text(10000)) == 10000


def test_attack_text_starts_with_the_attack_and_keeps_the_size() -> None:
    text = components.attack_text(200)
    assert text.startswith(components.ATTACK)
    assert len(text) == 200


def test_percentile_picks_the_ranked_value() -> None:
    values = [float(n) for n in range(1, 101)]
    assert components.percentile(values, 0.99) == 100.0
    assert components.percentile(values, 0.5) == 51.0


def test_summary_reports_every_arm_median_next_to_the_overall_one() -> None:
    summary = components.summarize("step", [[1.0, 2.0, 3.0], [10.0, 20.0, 30.0]])
    assert summary["calls"] == 6
    assert summary["max_us"] == 30.0
    assert summary["arm_medians_us"] == [2.0, 20.0]


def test_cpu_samples_returns_one_value_per_call() -> None:
    calls: list[int] = []
    samples = components.cpu_samples(lambda: calls.append(1), 5)
    assert len(samples) == 5
    assert len(calls) == 5


def test_ban_store_memory_counts_every_distinct_address() -> None:
    import tracemalloc

    from perf_gate import ban_store_memory

    tracemalloc.start()
    try:
        held, size = ban_store_memory.held_bytes(50, "4")
        held6, _ = ban_store_memory.held_bytes(50, "6")
    finally:
        tracemalloc.stop()
    assert held == 50
    assert held6 == 50
    assert size > 0


def test_multipart_cells_build_a_body_of_the_requested_size_for_every_shape() -> None:
    from perf_gate import multipart_cells

    for shape in ("mp-flat", "mp-escaped", "mp-binary"):
        body, content_type = multipart_cells.build_multipart(shape, 4096)
        assert len(body) == 4096
        assert content_type == (
            f"multipart/form-data; boundary={multipart_cells.BOUNDARY}"
        )
        assert body.endswith(f"--{multipart_cells.BOUNDARY}--\r\n".encode())


def test_multipart_cells_leave_out_the_settings_an_older_engine_lacks() -> None:
    from perf_gate import multipart_cells

    older = multipart_cells._config_kwargs(1048576, {"enable_redis", "rate_limit"})
    newer = multipart_cells._config_kwargs(
        1048576, {"enable_redis", "rate_limit", "async_body_read_max_concurrent"}
    )
    assert set(older) == {"enable_redis", "rate_limit"}
    assert newer["async_body_read_max_concurrent"] == multipart_cells.SLOTS


def test_multipart_cells_count_every_refusal_by_its_reason() -> None:
    from perf_gate import multipart_cells

    multipart_cells._REFUSAL_REASONS.clear()
    assert multipart_cells._note_refusal(200, "ok") == 200
    assert multipart_cells._note_refusal(400, " Bad request \n") == 400
    assert multipart_cells._note_refusal(400, "Bad request") == 400
    assert multipart_cells._REFUSAL_REASONS == {"400 Bad request": 2}
    multipart_cells._REFUSAL_REASONS.clear()
