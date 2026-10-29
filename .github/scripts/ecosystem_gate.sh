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

gate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
expected_dir="$gate_dir/../ecosystem-gate/expected"
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

# The consumer's .python-version says 3.11, so the job's interpreter is passed to uv explicitly.
python_version="${UV_PYTHON:?UV_PYTHON must name the interpreter this job tests}"
echo "::group::uv sync --python $python_version $sync_extra"
unlocked_resolution=0
if [ -f uv.lock ]; then
  uv sync --locked --python "$python_version" "${sync_args[@]}"
elif [ "$consumer_ref" = "latest-release" ]; then
  echo "::notice::$repo@$ref predates its committed uv.lock; resolving it as a user installing the release does (uv sync, 7-day cooldown)"
  uv sync --exclude-newer "7 days" --python "$python_version" "${sync_args[@]}"
  unlocked_resolution=1
else
  echo "::error::$repo@$ref has no committed uv.lock, so uv sync --locked cannot run" >&2
  exit 1
fi
.venv/bin/python -V
actual_python="$(.venv/bin/python -c "import sys; print('%d.%d' % sys.version_info[:2])")"
if [ "$actual_python" != "$python_version" ]; then
  echo "Expected the consumer venv on Python $python_version, got $actual_python" >&2
  exit 1
fi
echo "::endgroup::"

# COLUMNS keeps pytest from truncating the failure message in the short summary, which the expected-failures judging reads.
run_env=(IPINFO_TOKEN="${IPINFO_TOKEN:-test_token}" REDIS_URL="${REDIS_URL:-redis://localhost:6379}" COLUMNS=1000)
if [ -n "$redis_prefix" ]; then
  run_env+=(REDIS_PREFIX="$redis_prefix")
fi

if [ "$consumer_ref" = "latest-release" ]; then
  echo "::group::D-216 cap proof for $repo@$ref"
  consumer_dist="$(basename "$repo")"
  .venv/bin/python -c "import importlib.metadata as m, sys; print('\n'.join(m.requires(sys.argv[1]) or []))" "$consumer_dist" > "$PWD/tag-requires.txt"
  set +e
  uv run --no-project --python "$python_version" --with packaging python "$gate_dir/ecosystem_gate_cap_proof.py" \
    "$consumer_dist" "${ref#v}" "$expected_version" "$wheel_dir" "$python_version" "$PWD/tag-requires.txt"
  cap_status=$?
  set -e
  echo "::endgroup::"
  if [ "$cap_status" -ne 0 ]; then
    exit 1
  fi
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

# D-216: the latest-release leg judges the candidate run against the committed expected-failures list for this consumer@tag.
judge_expected=0
if [ "$consumer_ref" = "latest-release" ]; then
  judge_expected=1
fi

if [ "$candidate_only_count" -gt 0 ]; then
  ids_joined="$(paste -sd ',' "$work_dir/candidate_only.txt")"
  if [ "$judge_expected" -eq 1 ]; then
    echo "::notice::${repo}@${ref}: ${candidate_only_count} test(s) fail only with the PR wheel, judged against the expected-failures list: ${ids_joined}"
  else
    echo "::error::${repo}@${ref}: ${candidate_only_count} test(s) fail only with the PR wheel (regression): ${ids_joined}"
    job_status=1
  fi
fi

if [ "$judge_expected" -eq 1 ]; then
  if ! python3 "$gate_dir/ecosystem_gate_judge.py" "$candidate_output" "$expected_dir/$(basename "$repo")@${ref}.json"; then
    job_status=1
  fi
fi

if [ "$both_count" -gt 0 ]; then
  ids_joined="$(paste -sd ',' "$work_dir/both.txt")"
  if [ "$unlocked_resolution" -eq 1 ]; then
    # An unlocked resolution that breaks the base suite tests nothing about the release: fail rather than pass over it.
    echo "::error::baseline broken on ${repo}@${ref} under the unlocked resolution: ${both_count} tests fail without the PR wheel: ${ids_joined}"
    job_status=1
  else
    echo "::warning::baseline broken on ${repo}@${ref}: ${both_count} tests fail without the PR wheel: ${ids_joined}"
  fi
fi

if [ "$base_only_count" -gt 0 ]; then
  ids_joined="$(paste -sd ',' "$work_dir/base_only.txt")"
  echo "::notice::${repo}@${ref}: ${base_only_count} test(s) only failed on base, fixed by the PR wheel: ${ids_joined}"
fi

if [ "$candidate_status" -ne 0 ] && [ "$candidate_status" -ne 1 ]; then
  if [ "$candidate_status" -eq "$base_status" ] && [ "$unlocked_resolution" -eq 1 ]; then
    echo "::error::${repo}@${ref}: both runs exited abnormally with status $candidate_status under the unlocked resolution"
    job_status=1
  elif [ "$candidate_status" -eq "$base_status" ]; then
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

if [ "$job_status" -eq 0 ] && [ "$judge_expected" -eq 0 ] && { [ "$both_count" -gt 0 ] || [ "$candidate_status" -ne 0 ]; }; then
  echo "::warning::JOB PASSED OVER PRE-EXISTING ${repo}@${ref} FAILURES: ${both_count} test(s) fail identically with and without the PR wheel, so this PR introduces no regression there; the breakage belongs to ${repo}@${ref} itself. Inspect the pytest-output-base / pytest-output-candidate artifacts for the failing tests."
fi

exit "$job_status"
