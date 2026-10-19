import json
import unicodedata
from pathlib import Path

import pytest

from guard_core.handlers import _suspatterns_probe_names as generated
from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from guard_core.handlers._suspatterns_probe_chains import PROBE_CHAIN_ROW
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.wordlists.fetch import git_blob_sha
from tests.wordlists.probe_regex import any_depth_regexes, upload_only_regexes

WORDLISTS = (
    next(p for p in Path(__file__).resolve().parents if p.name == "tests") / "wordlists"
)
SOURCES = json.loads((WORDLISTS / "SOURCES.json").read_text(encoding="utf-8"))
CLASSIFICATION = json.loads((WORDLISTS / "classification.json").read_text("utf-8"))
BASELINE = json.loads(
    (WORDLISTS / "quickhits_flagged_5c38dc89.json").read_text("utf-8")
)
EXCLUSIONS = json.loads((WORDLISTS / "quickhits_exclusions.json").read_text("utf-8"))
BACKDOOR_LISTS = (
    "backdoor_list.txt",
    "CommonBackdoors-PHP.fuzz.txt",
    "CommonBackdoors-ASP.fuzz.txt",
    "CommonBackdoors-JSP.fuzz.txt",
    "CommonBackdoors-PL.fuzz.txt",
)
ANY_DEPTH = [
    row["name"] for row in CLASSIFICATION["names"] if row["mode"] == "any_depth"
]
UPLOAD_ONLY = [
    row["name"] for row in CLASSIFICATION["names"] if row["mode"] == "upload_only"
]


NAMED_AT_ANY_DEPTH_BY_OLDER_ROWS = {"phpinfo.php", "test.php"}


async def _flagged(path: str) -> bool:
    result = await detect_penetration_attempt(
        MockGuardRequest(path=path), SecurityConfig()
    )
    return result.is_threat


def _vendored() -> list[str]:
    return [local for local, meta in SOURCES["files"].items() if meta.get("vendored")]


@pytest.mark.parametrize("local", _vendored())
def test_vendored_list_matches_its_pinned_blob_sha(local: str) -> None:
    content = (WORDLISTS / local).read_bytes()
    assert git_blob_sha(content) == SOURCES["files"][local]["git_blob_sha"]
    assert len(content) == SOURCES["files"][local]["size"]
    assert b"<html" not in content[:512].lower()


def test_classification_records_the_pinned_commit_and_blob_shas() -> None:
    assert CLASSIFICATION["seclists_commit"] == SOURCES["commit"]
    for local, sha in CLASSIFICATION["blob_shas"].items():
        assert SOURCES["files"][local]["git_blob_sha"] == sha


def test_the_generated_rows_are_rebuilt_from_the_classification_table() -> None:
    assert list(generated.SCRIPT_NAMES_ANY_DEPTH_RES) == any_depth_regexes(ANY_DEPTH)
    assert list(generated.SCRIPT_NAMES_UPLOAD_ONLY_RES) == upload_only_regexes(
        UPLOAD_ONLY
    )


def test_the_joined_constants_are_the_halves_in_one_alternation() -> None:
    assert generated.SCRIPT_NAMES_ANY_DEPTH_RE == "|".join(
        generated.SCRIPT_NAMES_ANY_DEPTH_RES
    )
    assert generated.SCRIPT_NAMES_UPLOAD_ONLY_RE == "|".join(
        generated.SCRIPT_NAMES_UPLOAD_ONLY_RES
    )


def test_the_pattern_table_carries_the_generated_rows_and_the_one_chain_row() -> None:
    sources = {definition[0] for definition in _PATTERN_DEFINITIONS}
    assert set(generated.SCRIPT_NAMES_ANY_DEPTH_RES) <= sources
    assert set(generated.SCRIPT_NAMES_UPLOAD_ONLY_RES) <= sources
    assert PROBE_CHAIN_ROW in sources


def test_every_name_comes_from_a_vendored_backdoor_list() -> None:
    listed = set()
    for local in BACKDOOR_LISTS:
        for line in (WORDLISTS / local).read_text(encoding="utf-8").splitlines():
            base = line.strip().split("/")[-1]
            listed.add(" ".join(unicodedata.normalize("NFKC", base).split()).lower())
    for row in CLASSIFICATION["names"]:
        assert " ".join(row["name"].split()).lower() in listed


def test_the_decided_webshell_names_match_at_any_depth() -> None:
    by_name = {row["name"]: row["mode"] for row in CLASSIFICATION["names"]}
    assert by_name["c99.php"] == "any_depth"
    assert by_name["r57.php"] == "any_depth"
    assert by_name["shell.php"] == "upload_only"
    assert by_name["cmd.php"] == "upload_only"


async def test_listed_script_names_are_flagged_at_the_root_and_nested() -> None:
    missed = []
    for name in ANY_DEPTH:
        for path in (f"/{name}", f"/app/tools/{name}"):
            if not await _flagged(path):
                missed.append(path)
    assert missed == []


async def test_names_that_are_also_application_files_are_flagged_only_in_uploads() -> (
    None
):
    wrongly_flagged = []
    missed = []
    for name in UPLOAD_ONLY:
        if name not in NAMED_AT_ANY_DEPTH_BY_OLDER_ROWS and await _flagged(
            f"/api/{name}"
        ):
            wrongly_flagged.append(name)
        if not await _flagged(f"/uploads/{name}"):
            missed.append(name)
    assert wrongly_flagged == []
    assert missed == []


async def test_names_with_spaces_are_flagged_decoded_and_percent_encoded() -> None:
    spaced = [name for name in ANY_DEPTH if " " in name]
    assert spaced
    missed = []
    for name in spaced:
        for path in (f"/{name}", "/" + name.replace(" ", "%20")):
            if not await _flagged(path):
                missed.append(path)
    assert missed == []


CHAIN_PROBES = [
    "/fckeditor/editor/filemanager/connectors/php/connector.php",
    "/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp",
    "/site/fckeditor/editor/filemanager/connectors/aspx/upload.aspx",
    "/ckfinder/core/connector/php/connector.php",
    "/kcfinder/browse.php",
    "/admin/kcfinder/browse.php?type=files",
    "/elfinder/elfinder.php",
    "/ajaxfilemanager/ajaxfilemanager.php",
    "/spaw/dialogs/dialog.php",
    "/spaw2/dialogs/dialog.php",
    "/phpmyadmin/scripts/setup.php",
    "/pma/scripts/setup.php",
    "/myadmin/scripts/setup.php",
    "/adminer.php",
    "/tools/adminer.php",
    "/_mmServerScripts/MMHTTPDB.asp",
    "/_mmServerScripts/MMHTTPDB.php",
    "/web-console/ServerInfo.jsp",
    "/tmp/x.php",
    "/tmp/backup.sh",
    "/admin/bootstrap.inc.php?mgp=danc3Uf@t&c=whoami",
    "/admin/editor/dialogs/dialog.php?module=spawfm&dialog=spawfm&theme=spaw2lite&type=imagesundefined",
    "/admin/scripts/setup.php",
    "/admin/uploadarticles/uploadTester.asp",
    "/apc/apc.php",
    "/apc/index.php",
    "/billing/killer.php",
    "/bitrix/admin/i.php",
    "/bitrix/admin/index.php",
    "/bitrix/admin/p.php",
    "/bitrix/admin/php.php",
    "/bitrix/modules/main/admin/restore.php",
    "/bitrix/modules/main/classes/mysql/agent.php",
    "/bitrix/rk.php?goto=http://evil.com",
    "/cache/sql_error_latest.cgi",
    "/classes/adodb/server.php",
    "/cliente/downloads/h4xor.php",
    "/config/settings.inc",
    "/config/settings.ini.cfm",
    "/html/config.rb",
    "/lib/fileupload/fileBrowser.php",
    "/mysql/scripts/setup.php",
    "/mysqladmin/scripts/setup.php",
    "/scripts/setup.php",
    "/sqlbuddy/login.php",
    "/uploadarticles/uploadTester.asp",
    "/web/scripts/setup.php",
    "/webmail/src/configtest.php",
    "/whmcs/downloads/dz.php",
    "/wp.zip/nwp-content/plugins/disqus-comment-system/disqus.php",
    "/ws/api_test.php",
]

CHAIN_ORDINARY_ROUTES = [
    "/tmp",
    "/tmp/",
    "/tmp/report.pdf",
    "/api/tmp/x.php",
    "/shop/browse.php",
    "/dialogs/dialog.php",
    "/pma/index.php",
    "/myadmin/index.php",
    "/bitrix",
    "/bitrix24/admin/index.php",
    "/apc",
    "/apc/status",
    "/scripts/setup",
    "/wp.zipper",
    "/config.rb.txt",
    "/settings.inc.txt",
    "/api/bootstrap.inc",
    "/fileupload/browse.php",
    "/sqlbuddy",
    "/adodb/server",
    "/shop/connector.php",
    "/filemanager/connector.php",
    "/kcfinder",
    "/elfinder",
    "/adminer",
    "/web-console",
]


@pytest.mark.parametrize("path", CHAIN_PROBES)
async def test_named_probe_chains_are_flagged(path: str) -> None:
    assert await _flagged(path) is True


@pytest.mark.parametrize("path", CHAIN_ORDINARY_ROUTES)
async def test_ordinary_routes_sharing_a_chain_prefix_are_not_flagged(
    path: str,
) -> None:
    assert await _flagged(path) is False


async def test_the_quickhits_baseline_is_flagged_or_excluded_with_a_reason() -> None:
    excluded = EXCLUSIONS["excluded"]
    assert all(reason.strip() for reason in excluded.values())
    still_flagged = [name for name in BASELINE["flagged"] if await _flagged("/" + name)]
    lost = sorted(set(BASELINE["flagged"]) - set(still_flagged))
    assert lost == sorted(excluded)


async def test_the_excluded_entries_stay_unflagged_so_a_stale_reason_fails() -> None:
    flagged_now = [
        name for name in EXCLUSIONS["excluded"] if await _flagged("/" + name)
    ]
    assert flagged_now == []
