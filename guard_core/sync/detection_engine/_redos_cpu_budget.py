from dataclasses import dataclass


@dataclass(slots=True)
class ReachProbeCpuBudget:
    remaining_seconds: float

    def charge(self, cpu_seconds: float) -> None:
        self.remaining_seconds -= cpu_seconds
