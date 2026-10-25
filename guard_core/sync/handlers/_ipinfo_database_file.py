from __future__ import annotations

import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from maxminddb import Reader


class IpInfoDatabaseFileMixin:
    db_path: Path
    logger: logging.Logger

    _database_tmp_path: Callable[[], Path]

    def _open_database_or_none(self) -> Reader | None:
        import maxminddb

        try:
            return maxminddb.open_database(str(self.db_path))
        except Exception as e:
            self.logger.error(
                f"IPInfo database at {self.db_path} is corrupted, removing: {e}"
            )
            if self.db_path.exists():
                self.db_path.unlink()
            return None

    def _validate_database_file(self, path: Path) -> None:
        import maxminddb

        try:
            reader = maxminddb.open_database(str(path))
            try:
                reader.get("192.0.2.1")
            finally:
                reader.close()
        except OSError:
            raise
        except Exception as e:
            raise ValueError(f"not a usable GeoIP database: {e}") from e

    def _install_database_file(self, tmp_path: Path) -> None:
        try:
            self._validate_database_file(tmp_path)
            os.replace(tmp_path, self.db_path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

    def _write_database_atomically(self, content: bytes) -> None:
        tmp_path = self._database_tmp_path()
        try:
            with open(tmp_path, "wb") as f:
                f.write(content)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
        self._install_database_file(tmp_path)
