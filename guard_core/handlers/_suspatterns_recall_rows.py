from guard_core.handlers._suspatterns_file_upload import (
    _FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION,
    _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION,
)

_INTERNAL_IPV4_PREFIX_RE = (
    r"(?:127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})"
)

_CMD_EXTENDED_COMMAND_RE = (
    r"[;|&]\s*(?![^sSeEpPcCnNdDiItT])(?:sleep\s+\d+"
    r"|(?-i:env|printenv)\s*(?:[|;&>]|\Z)"
    r"|cmd(?:\.exe)?\s+/[a-z]"
    r"|(?:powershell(?:\.exe)?|pwsh)\s+-\w"
    r"|(?:ping|ncat)\s+-[a-z]"
    r"|(?:nslookup|dig)\s+[\w.-]+\.[a-z]{2,}"
    r"|ifconfig\s*(?:[|;&>]|\Z)"
    r"|telnet\s+[\w.-]+\s+\d+"
    r"|ssh\s+[\w.-]+@[\w.-]+)"
)
_CMD_NEWLINE_COMMAND_RE = r"\n[^\S\n]*(?-i:id|whoami|uname\s+-a)[^\S\n]*(?:[|;&]|\Z)"
_CMD_NEWLINE_COMMAND_DECODED_RE = _CMD_NEWLINE_COMMAND_RE + r"(?#url-decoded view)"
_CMD_EXFILTRATION_RE = (
    r"\bwget\s[^\n|;&]{0,80}--post-file(?:\s+|\s*=\s*)\S"
    r"|\bcurl\s[^\n|;&]{0,80}(?:--upload-file|-T)(?:\s+|\s*=\s*)[\"']?/\w"
    r"|\bcurl\s[^\n|;&]{0,80}(?:--data(?:-binary|-raw|-urlencode)?|-d|--form|-F)"
    r"(?:\s+|\s*=\s*)[\"']?(?:\w+=)?@/\w"
)

_CMD_PATH_SEPARATOR_COMMAND_RE = (
    r"[;|&]\s*(?=[lLcCrRiIwWuUnNsSbBpP])"
    r"(?:ls|cat|rm|id|whoami|uname|wget|curl|nc|netcat|socat|bash|sh"
    r"|python|perl)(?![\w.=:/\\-])"
    r"(?!\s+(?:is|are|was|were|be|am|has|have|had|does|do|did|will|would|can|could"
    r"|should|may|might|and|or|the|a|an|to|of|in|on|for|as|at|by|it|its|that|this"
    r"|which|with|from|not|but|if|so)\s)"
)

_CMD_PATH_CODE_EXECUTION_RE = (
    r"`[^`\n]{1,200}`|\b(?:eval|system|exec)\s*\(|\b(?:ba|z|da|k)?sh\s+-c\b"
)

_ABSOLUTE_PATH_VALUE_RE = (
    r"\A\s*(?:"
    r"/(?:etc|proc|root|boot)/[^/\s]"
    r"|/dev/(?:mem|kmem|port|null|zero|full|random|urandom|shm|mapper|disk|pts|tty"
    r"|console|fd|stdin|stdout|stderr|kvm|fuse|net|loop|sd[a-z]|hd[a-z]|vd[a-z]"
    r"|xvd[a-z]|nvme|snd|input|dri|watchdog|rtc|tun|usb|bus)"
    r"|/sys/(?:kernel|class|devices|fs|power|module|firmware|bus|block|dev"
    r"|hypervisor)(?:/|\s*\Z)"
    r"|/(?:var|usr)/(?:account|cache|crash|games|lib|lib32|lib64|libexec|lock|log"
    r"|mail|opt|run|spool|tmp|yp|bin|include|local|sbin|share|src|www|backups|db"
    r"|empty|adm)(?:/|\s*\Z)"
    r"|/home/(?:[^/\s]+/){0,12}\.[^/.\s][^/\s]*"
    r"|/(?:opt|srv)/(?:[^/\s]+/){0,12}(?:\.[^/.\s][^/\s]*|[^/\s]*\.\w{1,8})"
    r"(?:/|\s*\Z)"
    r"|(?!c:[/\\]fakepath[/\\])[a-z]:[/\\]\S"
    r"|\\\\[\w.$-]+\\[\w.$-]+)"
)

_TEMPLATE_DUNDER_CHAIN_RE = (
    r"\{\{[^{}]{0,200}__(?:class|globals|init|subclasses|mro|builtins|import|base"
    r"|bases|getattribute)__"
)
_TEMPLATE_FREEMARKER_EXECUTE_RE = (
    r"<#assign\s+\w+\s*=\s*[\"'][^\"']{0,120}(?:freemarker\.template\.utility"
    r"|ObjectConstructor|Execute|JythonRuntime)[^\"']{0,60}[\"']\s*\?\s*new\b"
)
_TEMPLATE_VELOCITY_SET_RE = (
    r"#set\s*\(\s*\$\w+\s*=\s*(?:\d+\s*[*+/-]\s*\d+"
    r"|[^)]{0,80}(?:\.getClass\(|forName\(|Runtime))"
)
_TEMPLATE_SPEL_SELECTION_RE = (
    r"\*\{\s*(?:\d+\s*[*+/-]\s*\d+\s*\}|T\s*\(\s*[A-Za-z_][\w.]*\s*\))"
)
_TEMPLATE_OGNL_RE = (
    r"%\{\s*\(\s*#[\w.]+\s*=|@ognl\.OgnlContext@|#(?:_memberAccess|context)\s*[\[=]"
)

_SQLI_ERROR_BASED_RE = r"\b(?:extractvalue|updatexml)\s*\(\s*[\w.]+\s*,\s*[^)]{0,80}"
_SQLI_SCHEMA_SUBSELECT_RE = (
    r"\(\s*select\b(?:[^()]|\([^()]*\)){0,100}\bfrom\s+information_schema\s*\.\s*"
    r"(?:tables|columns|schemata)"
)
_SQLI_BLIND_SUBSTRING_RE = (
    r"\b(?:substring|substr|mid)\s*\(\s*\(\s*select\b"
    r"|\bascii\s*\(\s*(?:substring|substr|mid)\s*\("
)

_SSRF_WILDCARD_DNS_RE = (
    r"(?:\A|[/@\s])" + _INTERNAL_IPV4_PREFIX_RE + r"\.(?:nip|sslip|xip)\.io\b"
)

_SSRF_INTERNAL_HOST_RE = (
    r"(?:localhost\.?|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1?\]|10(?:\.\d{1,3}){3}"
    r"|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|169\.254(?:\.\d{1,3}){2}|metadata\.google\.internal)"
)
_SSRF_FRAGMENT_USERINFO_RE = (
    r"://" + _SSRF_INTERNAL_HOST_RE + r"(?::\d+)?#@[^\s/@#]+"
    r"|://[^\s/@#]+#@" + _SSRF_INTERNAL_HOST_RE + r"(?::\d+)?(?:[/?\s]|\Z)"
)

_DESERIALIZATION_YAML_PYTHON_RE = r"!!(?:python|ruby)/(?:object|name|module)\b"
_PROTO_POLLUTION_CONSTRUCTOR_PROTOTYPE_RE = (
    r"[\"']constructor[\"']\s*:\s*\{\s*[\"']prototype[\"']"
    r"|\bconstructor\s*\.\s*prototype\s*\.\s*\w+\s*="
)

_FILE_INCLUSION_REMOTE_NULL_TERMINATED_RE = (
    r"\Ahttps?://[^\s/?#]+/[^\s?#]*\.(?:txt|php\d?|inc|jpg|png|gif|asp|jsp|pl|py|sh)"
    r"\?\Z"
)

_HTTP_SPLIT_CRLF_DECODED_RE = (
    r"[\r\n][^\S\r\n]*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)(?#url-decoded view)"
)

_FILE_UPLOAD_BARE_NAME_RE = (
    r"\A[\w.\-]{0,100}\.(?:"
    + _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION
    + r")(?:\.(?:"
    + _FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION
    + r")|;[^/\\]{0,60}|\.|\s+)\Z"
)

_RECON_CHANGELOG_BARE_RE = r"\A[/\\]?(?-i:CHANGELOG|ChangeLog)(?:\?\S*)?\s*\Z"
_RECON_SYSTEM_PROBE_FILES_RE = (
    r"\A[/\\]system[/\\](?:cron[/\\]cron\.txt|error\.txt)(?:\?\S*)?\s*\Z"
)
_CMS_UPLOADS_SCRIPT_RE = (
    r"\A[/\\]?(?:[\w.\-~%]+[/\\])*wp-content[/\\]uploads[/\\]"
    r"(?:[\w.\-~%]+[/\\])*[\w.\-~%]*\.php(?:\?\S*)?\s*\Z"
)
_CMS_UPLOADS_DIRECTORY_RE = (
    r"\A[/\\]?(?:[\w.\-~%]+[/\\])*wp-content[/\\]uploads[/\\]?(?:\?\S*)?\s*\Z"
)
