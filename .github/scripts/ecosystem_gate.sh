#!/usr/bin/env bash
set -euo pipefail

repo="$1"
sync_extra="$2"
pytest_args="$3"
read -r -a sync_args <<< "$sync_extra"
read -r -a pytest_arg_list <<< "$pytest_args"
wheel_dir="$4"
expected_version="$5"
redis_prefix="${6:-}"
consumer_ref="${7:-}"

clone_dir="consumer"
base_output="pytest-output-base.txt"
candidate_output="pytest-output-candidate.txt"

resolve_latest_release_tag() {
  local repo="$1" tag
  tag="$(gh api "repos/$repo/releases/latest" --jq '.tag_name' 2>/dev/null || true)"
  if [ -z "$tag" ] || [ "$tag" = "null" ]; then
    echo "gh api releases/latest returned nothing, falling back to tag version-sort" >&2
    tag="$(
      git ls-remote --tags "https://github.com/$repo" \
        | grep -v '\^{}' \
        | awk -F'refs/tags/' '{print $2}' \
        | while read -r t; do echo "${t#v} $t"; done \
        | sort -rV -k1,1 \
        | head -1 \
        | awk '{print $2}'
    )"
  fi
  echo "$tag"
}

extract_failed_ids() {
  local file="$1"
  awk '
    /^=+ short test summary info =+$/ { insummary=1; next }
    insummary && /^=+.*=+$/ { insummary=0 }
    insummary && (/^FAILED / || /^ERROR /) {
      line = $0
      sub(/^FAILED /, "", line)
      sub(/^ERROR /, "", line)
      sub(/ - .*/, "", line)
      print line
    }
  ' "$file" | sort -u
}

run_pytest_pass() {
  local outfile="$1"
  set +e
  # --no-sync: a plain `uv run` re-syncs to the lockfile and would put PyPI guard-core back over the PR wheel.
  env "${run_env[@]}" uv run --no-sync pytest "${pytest_arg_list[@]}" -rfE 2>&1 | tee "$outfile"
  pass_status="${PIPESTATUS[0]}"
  set -e
}

echo "::group::Resolve $repo ref (consumer_ref=${consumer_ref:-<default branch>})"
if [ -z "$consumer_ref" ]; then
  ref="$(gh api "repos/$repo" --jq '.default_branch')"
elif [ "$consumer_ref" = "latest-release" ]; then
  ref="$(resolve_latest_release_tag "$repo")"
else
  ref="$consumer_ref"
fi
if [ -z "$ref" ]; then
  echo "Could not resolve a ref for $repo" >&2
  exit 1
fi
echo "Resolved ref for $repo: $ref"
echo "::endgroup::"

echo "::group::Clone $repo@$ref"
git clone --branch "$ref" --depth 1 "https://github.com/$repo" "$clone_dir"
cd "$clone_dir"
echo "::endgroup::"

echo "::group::uv sync $sync_extra"
if [ ! -f uv.lock ]; then
  echo "::error::$repo@$ref has no committed uv.lock, so uv sync --locked cannot run" >&2
  exit 1
fi
uv sync --locked "${sync_args[@]}"
echo "::endgroup::"

run_env=(IPINFO_TOKEN="${IPINFO_TOKEN:-test_token}" REDIS_URL="${REDIS_URL:-redis://localhost:6379}")
if [ -n "$redis_prefix" ]; then
  run_env+=(REDIS_PREFIX="$redis_prefix")
fi

echo "::group::Run $repo's test suite (base: guard-core as resolved from PyPI)"
run_pytest_pass "$base_output"
base_status="$pass_status"
echo "base pytest run exited with status $base_status"
echo "::endgroup::"

echo "::group::Force-install the PR guard-core wheel"
wheel="$(ls "$wheel_dir"/*.whl)"
echo "Installing $wheel over whatever guard-core $repo resolved"
uv pip install --python .venv/bin/python --no-deps --force-reinstall "$wheel"
echo "::endgroup::"

echo "::group::Assert guard-core is the PR build"
actual_version="$(.venv/bin/python -c "import guard_core, importlib.metadata as m; print(m.version('guard-core'))")"
echo "guard-core version resolved by $repo's venv: $actual_version"
if [ "$actual_version" != "$expected_version" ]; then
  echo "Expected guard-core $expected_version, got $actual_version" >&2
  exit 1
fi

guard_core_file="$(.venv/bin/python -c "import guard_core; print(guard_core.__file__)")"
venv_abs="$(cd .venv && pwd)"
echo "guard_core.__file__ = $guard_core_file"
case "$guard_core_file" in
  "$venv_abs"/*) ;;
  *)
    echo "guard_core did not load from $repo's own venv ($venv_abs): $guard_core_file" >&2
    exit 1
    ;;
esac
echo "::endgroup::"

echo "::group::Run $repo's test suite (candidate: PR wheel force-installed)"
run_pytest_pass "$candidate_output"
candidate_status="$pass_status"
echo "candidate pytest run exited with status $candidate_status"
version_after_run="$(.venv/bin/python -c "import importlib.metadata as m; print(m.version('guard-core'))")"
if [ "$version_after_run" != "$expected_version" ]; then
  echo "::error::guard-core was $version_after_run after the candidate run, expected the PR build $expected_version" >&2
  exit 1
fi
echo "::endgroup::"

echo "::group::Diff base vs candidate failures for $repo@$ref"
work_dir="$(mktemp -d)"
extract_failed_ids "$base_output" > "$work_dir/base_ids.txt"
extract_failed_ids "$candidate_output" > "$work_dir/candidate_ids.txt"
comm -13 "$work_dir/base_ids.txt" "$work_dir/candidate_ids.txt" > "$work_dir/candidate_only.txt"
comm -23 "$work_dir/base_ids.txt" "$work_dir/candidate_ids.txt" > "$work_dir/base_only.txt"
comm -12 "$work_dir/base_ids.txt" "$work_dir/candidate_ids.txt" > "$work_dir/both.txt"

candidate_only_count="$(wc -l < "$work_dir/candidate_only.txt" | tr -d ' ')"
base_only_count="$(wc -l < "$work_dir/base_only.txt" | tr -d ' ')"
both_count="$(wc -l < "$work_dir/both.txt" | tr -d ' ')"

job_status=0

if [ "$candidate_only_count" -gt 0 ]; then
  ids_joined="$(paste -sd ',' "$work_dir/candidate_only.txt")"
  echo "::error::${repo}@${ref}: ${candidate_only_count} test(s) fail only with the PR wheel (regression): ${ids_joined}"
  job_status=1
fi

if [ "$both_count" -gt 0 ]; then
  ids_joined="$(paste -sd ',' "$work_dir/both.txt")"
  echo "::warning::baseline broken on ${repo}@${ref}: ${both_count} tests fail without the PR wheel: ${ids_joined}"
fi

if [ "$base_only_count" -gt 0 ]; then
  ids_joined="$(paste -sd ',' "$work_dir/base_only.txt")"
  echo "::notice::${repo}@${ref}: ${base_only_count} test(s) only failed on base, fixed by the PR wheel: ${ids_joined}"
fi

if [ "$candidate_status" -ne 0 ] && [ "$candidate_status" -ne 1 ]; then
  if [ "$candidate_status" -eq "$base_status" ]; then
    echo "::warning::${repo}@${ref}: both runs exited abnormally with status $candidate_status (baseline already broken at collection)"
  else
    echo "::error::${repo}@${ref}: candidate pytest run exited abnormally (status $candidate_status) while base exited $base_status, treating as a job failure"
    job_status=1
  fi
fi

echo "Summary for ${repo}@${ref}"
printf '%-68s %6s\n' "Category" "Count"
printf '%-68s %6s\n' "--------------------------------------------------------------" "-----"
printf '%-68s %6s\n' "Candidate-only failures (blocks the gate)" "$candidate_only_count"
printf '%-68s %6s\n' "Failing on base and candidate (baseline already broken)" "$both_count"
printf '%-68s %6s\n' "Base-only failures (fixed by the PR wheel)" "$base_only_count"
echo "::endgroup::"

if [ "$job_status" -eq 0 ] && { [ "$both_count" -gt 0 ] || [ "$candidate_status" -ne 0 ]; }; then
  echo "::warning::JOB PASSED OVER PRE-EXISTING ${repo}@${ref} FAILURES: ${both_count} test(s) fail identically with and without the PR wheel, so this PR introduces no regression there; the breakage belongs to ${repo}@${ref} itself. Inspect the pytest-output-base / pytest-output-candidate artifacts for the failing tests."
fi

exit "$job_status"
