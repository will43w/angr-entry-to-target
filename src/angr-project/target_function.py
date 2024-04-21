from typing import Callable, List

from angr.sim_type import SimTypeFunction
from angr.calling_conventions import SimFunctionArgument
from angr.analyses.cfg.cfg import CFG
from angr import SimState

class TargetFunction:
    def __init__(
        self,
        address: int,
        prototype: SimTypeFunction,
        satisfiability_check: Callable[[SimState, List[SimFunctionArgument]], bool]
    ):
        self.address = address
        self.prototype = prototype
        self._satisfiability_check = satisfiability_check

    def get_find_check(
        self, 
        arguments: List[SimFunctionArgument]
    ) -> Callable[[SimState], bool]:
        """
        Returns a callback for angr to evaluate whether or not a given state 
        meets the supplied `satisfiability_check` at the target.
        """
        
        def find(state):
            if state.addr != self.address:
                return False

            argument_values = [argument.get_value(state) for argument in arguments]
            return self._satisfiability_check(state, argument_values)
        
        return find
    
    def get_avoid_check(
        self,
        cfg: CFG
    ) -> Callable[[SimState], bool]:
        """
        Returns a callback for angr to evaluate whether or not to continue exploring
        children of this state. Namely, this condition is defined as whether or not 
        the target shows up in the state's block's control-flow sub-graph. 
        """

        target_node = cfg.model.get_any_node(self.address)
        def avoid(state):
            current_node = cfg.model.get_any_node(state.addr)
        
            if current_node is None:
                return False # TODO: What should be done here? What does `None` mean in this context?
            
            # TODO: Lots of duplicated work in `get_all_successors`. Can it be made more efficient?
            target_node_successors = cfg.model.get_all_successors(current_node)
            return target_node not in target_node_successors
        
        return avoid