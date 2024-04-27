from typing import List, Callable

from angr.sim_state import SimState
from angr import ExplorationTechnique
from angr.exploration_techniques import Explorer
from angr.analyses.cfg.cfg import CFG
from angr.analyses.complete_calling_conventions import CompleteCallingConventionsAnalysis
from angr import SimCC
from angr.calling_conventions import SimFunctionArgument
import angr

from .entry_function import EntryFunction
from .target_function import TargetFunction

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
        cca = self.project.analyses.CompleteCallingConventions(
            recover_variables=True,
            prioritize_func_addrs=[self.entry_function.address, self.target_function.address],
            skip_other_funcs=True,
            cfg=cfg,
            analyze_callsites=True)
        
        entry_calling_convention = cca.kb.functions.get_by_addr(self.entry_function.address).calling_convention
        state = self._setup_entry_state(entry_calling_convention)

        target_arguments = cca.kb.functions.get_by_addr(self.target_function.address).calling_convention.arg_locs(
             self.entry_function.prototype)
        explorer = self._setup_target_exploration(cfg, target_arguments)

        simulation_manager = self.project.factory.simulation_manager(state)
        simulation_manager.use_technique(explorer)
        simulation_manager.run()

        return simulation_manager.found
    
    def _setup_entry_state(
        self,
        entry_calling_convention: SimCC
    ) -> SimState:
        entry_address = self.entry_function.address
        state = self.project.factory.call_state(
            entry_address, 
            *(self.entry_function.arguments), 
            cc=entry_calling_convention, 
            prototype=self.entry_function.prototype) # providing `prototype` kwarg
        
        for constraint in self.entry_function.constraints:
                state.add_constraints(constraint)

        return state
    
    def _setup_target_exploration(
        self,
        cfg: CFG,
        target_arguments: List[SimFunctionArgument]
    ) -> ExplorationTechnique:
        explorer = TargetMethodAnalysis._get_exploration_technique(
             find_check=self.target_function.get_find_check(target_arguments),
             avoid_check=self.target_function.get_avoid_check(cfg),
             cfg=cfg)
        
        return explorer
    
    @staticmethod
    def _get_exploration_technique(
        find_check: Callable[[SimState], bool],
        avoid_check: Callable[[SimState], bool],
        cfg: CFG
    ) -> ExplorationTechnique:
        return Explorer(find=find_check, avoid=avoid_check, cfg=cfg)