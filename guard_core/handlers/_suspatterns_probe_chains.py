_SEP = r"[/\\]"
_CHAR = r"[\w.\-~%]"
_SEGMENTS = rf"(?:{_CHAR}+{_SEP})*"
_SUFFIX = rf"(?:{_SEP}{_CHAR}*)*(?:\?\S*)?\s*\Z"
_SCRIPT_EXTENSIONS = r"(?:asp|aspx|php|jsp|pl|cgi|sh)"

_NESTED_CHAINS = (
    rf"fckeditor{_SEP}editor{_SEP}filemanager{_SEP}{_SEGMENTS}"
    r"(?:connector|upload)\.(?:asp|aspx|php)",
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
)
_ROOT_TMP_SCRIPT = rf"tmp{_SEP}{_CHAR}+\.{_SCRIPT_EXTENSIONS}(?:\?\S*)?\s*\Z"

PROBE_CHAIN_ROW = (
    rf"\A{_SEP}?(?:{_ROOT_TMP_SCRIPT}"
    rf"|{_SEGMENTS}(?:{'|'.join(_NESTED_CHAINS)}){_SUFFIX})"
)
