from typing import Any

from angr.sim_type import SimType

class ValueWithType:
    def __init__(
        self,
        value: Any,
        type: SimType
    ):
        self.value = value
        self.Type = SimType

    def 