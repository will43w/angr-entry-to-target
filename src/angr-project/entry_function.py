from typing import List, Tuple, Optional, Generator, Union

from angr.sim_type import SimType, SimTypeFunction

from . import SymbolicValue, ConcreteValue, Constraint

class EntryFunctionArgument:
    def __init__(
        self,
        type: SimType,
        value: Union[SymbolicValue, ConcreteValue],
        constraints: List[Constraint] = None,
        name: Optional[str] = None
    ):
        self.type = type
        self.value = value
        self._constraints = constraints
        self.name = name

    @property
    def constraints(
        self,
    ) -> Generator[Constraint]:
        if self.constraints is None:
            return iter(())
        
        return self.constraints


class EntryFunction:
    def __init__(
        self,
        address: int,
        arguments: Tuple[EntryFunctionArgument, ...],
        return_type: Optional[SimType]
    ):
        self.address = address
        self._arguments = arguments
        self.prototype = SimTypeFunction(
            (arg.type for arg in arguments),
            return_type,
            arg_names=(arg.name for arg in arguments))
        
    @property
    def arguments(self) -> Generator[Union[SymbolicValue, ConcreteValue]]:        
        return (argument.value for argument in self._arguments)
    
    @property
    def constraints(self) -> Generator[Constraint]:
        for argument in self._arguments:
            for constraint in argument.constraints:
                yield constraint



