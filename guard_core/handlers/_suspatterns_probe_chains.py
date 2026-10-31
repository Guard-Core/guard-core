import re

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup

_SEP = r"[/\\]"
_CHAR = r"[\w.\-~%]"
_SEGMENTS = rf"(?:{_CHAR}+{_SEP})*"
_PATH_CHAR = r"[\w.\-~%/\\]"
_CHAIN_END = rf"(?!{_CHAR})"
_PATTERNS = LazyPatterns(
    {
        "_PATH_THEN_OPTIONAL_QUERY_THEN_SPACE": (rf"{_PATH_CHAR}*(?:\?\S*)?\s*\Z", 0),
    }
)
_lookup = module_attribute_lookup(_PATTERNS)


def __getattr__(name: str) -> re.Pattern[str]:
    return _lookup(name)


_SCRIPT_EXTENSIONS = r"(?:asp|aspx|php|jsp|pl|cgi|sh)"

_FCKEDITOR_PREFIX = rf"fckeditor{_SEP}editor{_SEP}filemanager{_SEP}"
_FCKEDITOR_TARGET = r"(?:connector|upload)\.(?:asp|aspx|php)"

_NESTED_CHAINS = (
    rf"{_FCKEDITOR_PREFIX}{_SEGMENTS}{_FCKEDITOR_TARGET}",
    rf"ckfinder{_SEP}core{_SEP}connector{_SEP}(?:asp|aspx|php){_SEP}"
    r"connector\.(?:asp|aspx|php)",
    rf"kcfinder{_SEP}browse\.php",
    rf"elfinder{_SEP}elfinder\.php",
    rf"ajaxfilemanager{_SEP}ajaxfilemanager\.php",
    rf"spaw2?{_SEP}dialogs{_SEP}dialog\.php",
    rf"editor{_SEP}dialogs{_SEP}dialog\.php",
    rf"scripts{_SEP}setup\.php",
    r"adminer\.php",
    rf"_mmServerScripts{_SEP}MMHTTPDB\.(?:asp|php)",
    rf"web-console{_SEP}ServerInfo\.jsp",
    rf"apc{_SEP}(?:apc|index)\.php",
    rf"bitrix{_SEP}(?:admin|modules|rk\.php)",
    rf"fileupload{_SEP}fileBrowser\.php",
    rf"(?:webmail|squirrelmail){_SEP}src{_SEP}configtest\.php",
    rf"adodb{_SEP}server\.php",
    rf"sqlbuddy{_SEP}(?:login|index)\.php",
    r"wp\.zip",
    r"uploadTester\.asp",
    r"(?:killer|h4xor|dz|api_test)\.php",
    r"bootstrap\.inc\.php",
    r"sql_error_latest\.cgi",
    r"(?:settings\.inc|settings\.ini\.cfm|config\.rb)",
    rf"(?:adm|admin|upload|plugins){_SEP}upload\.php",
    rf"admin{_SEP}(?:export|download)\.php",
    rf"app{_SEP}languages",
    rf"bin{_SEP}(?:config|reset-db|reset-db-prod)\.sh",
    rf"cron{_SEP}cron\.sh",
    rf"config{_SEP}(?:apc|config\.inc)\.php",
    rf"docs{_SEP}changelog\.txt",
    rf"demo{_SEP}sql{_SEP}index\.jsp",
    rf"downloads{_SEP}dom\.php",
    rf"maintenance{_SEP}test2\.php",
    rf"forum{_SEP}install{_SEP}install\.php",
    rf"inc{_SEP}config\.inc",
    rf"includes{_SEP}adovbs\.inc",
    rf"(?:pma|myadmin|sql){_SEP}index\.php",
    rf"sql{_SEP}db\.sql",
    rf"templates{_SEP}(?:beez|ja-helio-farsi|rhuk_milkyway){_SEP}index\.php",
)
_ROOT_TMP_SCRIPT = rf"tmp{_SEP}{_CHAR}+\.{_SCRIPT_EXTENSIONS}(?:\?\S*)?\s*\Z"

_LEADING_PLAIN_GROUP = re.compile(r"\(\?:([^()]*)\)(.*)", re.DOTALL)


def _expand_leading_group(chain: str) -> list[str]:
    leading = _LEADING_PLAIN_GROUP.fullmatch(chain)
    if leading is None:
        return [chain]
    return [option + leading[2] for option in leading[1].split("|")]


def _alternation_by_first_character(chains: tuple[str, ...]) -> str:
    by_first: dict[str, list[str]] = {}
    for chain in chains:
        for expanded in _expand_leading_group(chain):
            by_first.setdefault(expanded[0], []).append(expanded[1:])
    return "|".join(
        f"{first}(?:{'|'.join(rests)})" for first, rests in by_first.items()
    )


_FIRST_FCKEDITOR_START = (
    rf"(?=(?P<fckeditor_start>(?:{_CHAR}+{_SEP})*?{_FCKEDITOR_PREFIX}))"
    r"(?P=fckeditor_start)"
)

PROBE_CHAIN_ROW = (
    rf"\A{_SEP}?(?:{_ROOT_TMP_SCRIPT}"
    rf"|{_SEGMENTS}(?:{_alternation_by_first_character(_NESTED_CHAINS[1:])}){_CHAIN_END}"
    rf"|{_FIRST_FCKEDITOR_START}{_SEGMENTS}{_FCKEDITOR_TARGET}{_CHAIN_END})"
)


def chain_row_tail_is_query_or_space(match: re.Match[str]) -> bool:
    return (
        _PATTERNS["_PATH_THEN_OPTIONAL_QUERY_THEN_SPACE"].fullmatch(match.string)
        is not None
    )
