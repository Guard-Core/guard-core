from guard_core._config_capabilities import _extra_installed, install_hint
from guard_core.exceptions import DownloaderNotInstalledError

TREE_DOWNLOADER = "aiohttp"


def require_downloader_installed(
    extra: str, feature: str, adapter: str | None = None
) -> None:
    if not _extra_installed(TREE_DOWNLOADER):
        raise DownloaderNotInstalledError(
            f"{feature} needs '{TREE_DOWNLOADER}' in this tree and it is not "
            f"installed. Install it with: {install_hint(extra, adapter)}"
        )
