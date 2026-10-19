import time


class _Probe:
    def __init__(self, hold: float) -> None:
        self.hold = hold
        self.in_flight = 0
        self.peak = 0

    def read(self) -> bytes:
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            time.sleep(self.hold)
            return b"body"
        finally:
            self.in_flight -= 1
