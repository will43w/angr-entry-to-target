from typing import List, Callable, TypeVar, Any

from angr.sim_type import SimTypeFunction
from angr.calling_conventions import SimFunctionArgument

PayloadType = TypeVar("PayloadType")

class TargetMethodModel:
    def __init__(
        self, 
        payload: PayloadType,
        target_method_arguments: List[SimFunctionArgument],
        satisfiability_check: Callable[[List[Any], PayloadType], bool]
    ):
        self.payload = payload
        self.method_arguments = target_method_arguments
        self.satisfiability_check = satisfiability_check

    def paylaod_is_satisfiable(self, state):
        argument_values = [argument.get_value(state) for argument in self.method_arguments]
        return self.satisfiability_check(argument_values, self.payload)

