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

PROBE_CHAIN_ROW = (
    rf"\A{_SEP}?(?:{_ROOT_TMP_SCRIPT}"
    rf"|{_SEGMENTS}(?:{'|'.join(_NESTED_CHAINS)}){_SUFFIX})"
)
