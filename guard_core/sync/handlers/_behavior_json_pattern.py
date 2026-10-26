class BehaviorJsonPatternMixin:
    def _parse_pattern(self, pattern: str) -> tuple[str, str] | None:
        if "==" not in pattern:
            return None

        path, expected = pattern.split("==", 1)
        path = path.strip()
        expected = expected.strip().strip("\"'")
        return path, expected

    def _handle_array_match(self, current: object, part: str, expected: str) -> bool:
        part = part[:-2]

        if not isinstance(current, dict) or part not in current:
            return False

        current = current[part]
        if not isinstance(current, list):
            return False

        return any(str(item).lower() == expected.lower() for item in current)

    def _traverse_json_path(self, data: object, path: str) -> object | None:
        current = data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _match_json_pattern(self, data: object, pattern: str) -> bool:
        try:
            parsed = self._parse_pattern(pattern)
            if not parsed:
                return False

            path, expected = parsed

            current = data
            for part in path.split("."):
                if part.endswith("[]"):
                    return self._handle_array_match(current, part, expected)

                if not isinstance(current, dict) or part not in current:
                    return False
                current = current[part]

            return str(current).lower() == expected.lower()

        except Exception:
            return False
