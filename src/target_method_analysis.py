from typing import List, Callable, TypeVar, Any

from angr.sim_type import SimTypeFunction
from angr.sim_state import SimState
import angr

from target_method_model import TargetMethodModel
import execution_technique_generator

PayloadType = TypeVar("PayloadType")

class TargetMethodAnalysis: # TODO: Don't overload "Analysis" - angr already has a definition
    def __init__(
        self,
        path: str,
        entry_address: int,
        target_address: int,
        entry_prototype: SimTypeFunction,
        target_prototype: SimTypeFunction,
        payload: PayloadType,
        satisfiability_check: Callable[[List[Any], PayloadType], bool]
    ):
        self.project = angr.Project(path, load_options={'auto_load_libs':False})
        self.entry_address = entry_address
        self.target_address = target_address
        self.entry_prototype = entry_prototype
        self.target_prototype = target_prototype
        self.payload = payload
        self.satisfiability_check = satisfiability_check

    def run(self) -> List[SimState]:
        symbolic_input_generator = SymbolicInputGenerator(entry_calling_convention) # TODO: Symbolic input generator
        symbolic_arguments = symbolic_input_generator.create_symbolic_input()

        cfg = self.project.analyses.CFG(fail_fast=True)
        
        entry_variable_recovery = self.project.analyses.VariableRecoveryFast(self.entry_address) # Variable analysis required for calling convention analysis (?)
        entry_calling_convention = self.project.analyses.CallingConvention(self.entry_address)
        
        state = self.project.factory.call_state(
            self.entry_address, 
            *symbolic_arguments, 
            cc=entry_calling_convention.cc, 
            prototype=self.entry_prototype) # provide prototype kwarg
        
        symbolic_input_generator.constrain_symbolic_input(symbolic_arguments)

        # Calling convention, variables, and variable types of target function
        # https://github.com/angr/angr/issues/3125
        target_variable_recovery = self.project.analyses.VariableRecoveryFast(self.target_address) # Variable analysis required for calling convention analysis (?)
        target_calling_convention = self.project.analyses.CallingConvention(self.target_address) # Discover registers used to store function arguments

        target_method_arguments = target_calling_convention.cc.arg_locs(self.target_prototype)
        target_method_model = TargetMethodModel(
            self.payload,
            target_method_arguments,
            self.satisfiability_check)
        
        explorer = execution_technique_generator.get_explorer(
            self.target_address,
            target_method_model,
            cfg)

        simulation_manager = self.project.factory.simulation_manager(state)
        simulation_manager.use_technique(explorer)
        simulation_manager.run()

        return simulation_manager.found

