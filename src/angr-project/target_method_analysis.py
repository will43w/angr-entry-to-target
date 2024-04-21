from typing import List, Callable

from angr.sim_state import SimState
from angr import ExplorationTechnique
from angr.exploration_techniques import Explorer
from angr.analyses.cfg.cfg import CFG
import angr

from entry_function import EntryFunction
from target_function import TargetFunction

class TargetMethodAnalysis: # TODO: Don't overload "Analysis" - angr already has a definition
    def __init__(
        self,
        path: str,
        entry_function: EntryFunction,
        target_function: TargetFunction,
    ):
        self.project = angr.Project(path, load_options={'auto_load_libs':False})
        self.entry_function = entry_function
        self.target_function = target_function

    def run(self) -> List[SimState]:
        cfg = self.project.analyses.CFG(fail_fast=True)
        
        state = self._setup_entry_state(cfg)
        explorer = self._setup_target_exploration(cfg)

        simulation_manager = self.project.factory.simulation_manager(state)
        simulation_manager.use_technique(explorer)
        simulation_manager.run()

        return simulation_manager.found
    
    def _setup_entry_state(
        self,
        cfg: CFG
    ) -> SimState:
        entry_address = self.entry_function.address

        entry_variable_recovery = self.project.analyses.VariableRecoveryFast(entry_address) # TODO: Is variable analysis _required_ for calling convention analysis?
        entry_calling_convention = self.project.analyses.CallingConvention(entry_address) # Discover registers used to store function arguments
        
        state = self.project.factory.call_state(
            entry_address, 
            *self.entry_function.arguments, 
            cc=entry_calling_convention.cc, 
            prototype=self.entry_function.prototype) # providing `prototype` kwarg
        
        for constraint in self.entry_function.constraints:
                state.add_constraints(constraint)

        return state
    
    def _setup_target_exploration(
        self,
        cfg: CFG
    ) -> ExplorationTechnique:
        target_address = self.target_function.address

        # Calling convention, variables, and variable types of target function https://github.com/angr/angr/issues/3125
        target_variable_recovery = self.project.analyses.VariableRecoveryFast(target_address) # TODO: Is variable analysis _required_ for calling convention analysis?
        target_calling_convention = self.project.analyses.CallingConvention(target_address) # Discover registers used to store function arguments

        target_method_arguments = target_calling_convention.cc.arg_locs(self.target_function)
        explorer = TargetMethodAnalysis._get_exploration_technique(
             find_check=self.target_function.get_find_check(target_method_arguments),
             avoid_check=self.target_function.get_avoid_check(cfg),
             cfg=cfg
        )
        
        return explorer
    
    @staticmethod
    def _get_exploration_technique(
        find_check: Callable[[SimState], bool],
        avoid_check: Callable[[SimState], bool],
        cfg: CFG
    ) -> ExplorationTechnique:
        return Explorer(find=find_check, avoid=avoid_check, cfg=cfg)