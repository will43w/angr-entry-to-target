#!/usr/bin/env python

from target_method_analysis import TargetMethodAnalysis
from entry_function import *
from target_function import *

from angr.sim_type import *
from angr.calling_conventions import SimFunctionArgument

import angr
import claripy

def symbolic_filename():
    def get_address_from_symbol(funcName: str):
        # Hack over find_symbol - see https://github.com/angr/cle/issues/194
        addrs = project.loader.find_all_symbols(funcName)
        for addr in addrs:
            return addr.rebased_addr

    path = "/Users/william.hafner/dev/hello-rust/target/debug/hello-rust"

    # objdump --syms /Users/william.hafner/dev/hello-rust/target/debug/hello-rust | grep "file"
    entry_func_addr = get_address_from_symbol('__ZN10hello_rust23rpc_create_file_if_no_q17h35276a1d9d36e04eE')
    target_func_addr = get_address_from_symbol('__ZN10hello_rust11create_file17h57d00ed4135b8bafE')

    charstar = SimTypePointer(SimTypeChar())
    longlong = SimTypeLongLong()
    
    # Setup of entry method data
    max_filename_size = 40 # max number of bytes we'll try to solve for
    symbolic_filename = claripy.BVS('symbolic_filename', 8 * max_filename_size)
    symbolic_filename_size = claripy.BVS("symbolic_filename_size", 64)
    
    filename_pointer = EntryFunctionArgument(
        type = charstar,
        value = angr.PointerWrapper(symbolic_filename, buffer=True),
        name="filename_pointer"
    )
    filename_length = EntryFunctionArgument(
        type = longlong,
        value = symbolic_filename_size,
        constraints = (
            symbolic_filename_size >= 0,
            symbolic_filename_size <= max_filename_size
        ),
        name="filename_length",
    )
    return_type = longlong

    entry_function = EntryFunction(
        address = entry_func_addr,
        constrainted_argument_types = (filename_pointer, filename_length),
        return_type = return_type
    )

    # Setup of target method data
    target_func_prototype = SimTypeFunction((charstar, longlong), longlong)

    payload = rb'_hello_world_with.txq'
    def target_payload_satisfiability_check(state: SimState, target_arguments: List[Any]): 
        pointer = target_arguments[0]
        length = target_arguments[1]

        # If our string length can't be the desired length, we're unsat
        if not state.satisfiable(extra_constraints = (length == len(payload))):
            return False

        symbolic_payload = state.mem[pointer].with_type(SimTypeChar()).array(len(payload))
        return state.satisfiable(extra_constraints=(
            length == len(payload), 
            *[symbolic_payload[offset].resolved == byte for offset, byte in enumerate(payload)]))
    
    target_function = TargetFunction(
        address = target_func_addr,
        prototype = target_func_prototype,
        satisfiability_check = target_payload_satisfiability_check
    )
    
    target_method_analysis = TargetMethodAnalysis(
        path,
        entry_function,
        target_function
    )

    found = target_method_analysis.run()
    if len(found) > 0:
        print("Found path to target func!")
    else:
        print("Didn't find path to target func.")















def debug():
    def getFuncAddressFromSymbol(funcName: str):
        # Hack over find_symbol - see https://github.com/angr/cle/issues/194
        addrs = project.loader.find_all_symbols(funcName)
        for addr in addrs:
            repr(addr)
            print("rpc_create_file_if_no_q" 
                + "\n\trelative_addr: " + str(addr.relative_addr) 
                + "\n\tlinked_addr: " + str(addr.linked_addr)
                + "\n\tebased_addr: " + str(addr.rebased_addr)
                + "\n\tis_function: " + str(addr.is_function))
            return addr.rebased_addr

    project = angr.Project("/Users/william.hafner/dev/hello-rust/target/debug/hello-rust", load_options={'auto_load_libs':False})
    cfg = project.analyses.CFG(fail_fast=True)

    # memchr_func_addr = getFuncAddressFromSymbol('__ZN4core5slice6memchr14memchr_aligned17h038dbdb80d66e13bE')
    # memchr_variable_recovery = project.analyses.VariableRecoveryFast(memchr_func_addr) # Variable analysis required for calling convention analysis (?)
    # memchr_calling_convention = project.analyses.CallingConvention(memchr_func_addr)

    # objdump --syms /Users/william.hafner/dev/hello-rust/target/debug/hello-rust | grep "file"
    entry_func_addr = getFuncAddressFromSymbol('__ZN10hello_rust23rpc_create_file_if_no_q17h35276a1d9d36e04eE')
    target_func_addr = getFuncAddressFromSymbol('__ZN10hello_rust11create_file17h57d00ed4135b8bafE')

    argv = ["hello_world.txt"]
    state = project.factory.call_state(entry_func_addr, args=argv)
    simulation_manager = project.factory.simulation_manager(state)

    entry_variable_recovery = project.analyses.VariableRecoveryFast(entry_func_addr) # Variable analysis required for calling convention analysis (?)
    entry_calling_convention = project.analyses.CallingConvention(entry_func_addr)

    dummy_addr = 0x300000
    filename = rb'hello_world_with_.txt'
    #state.memory.store(dummy_addr, filename)

    sym_filename_size = 40 # max number of bytes we'll try to solve for
    sym_filename = claripy.BVS('sym_filename', 8 * sym_filename_size)
    sym_filename_size = claripy.BVS("sym_filename_size", 64) # PENCIL: Seems to only be evaluatable to multiples of 16 - check why
    state.add_constraints(sym_filename_size >= 0)
    state.add_constraints(sym_filename_size <= 1000)
    x0_arg = angr.PointerWrapper(sym_filename, buffer=True)
    x1_arg = sym_filename_size

    entry_calling_convention.cc.arg_locs(entry_calling_convention.prototype)[0].set_value(state, dummy_addr) 
    entry_calling_convention.cc.arg_locs(entry_calling_convention.prototype)[1].set_value(state, sym_filename_size) 
    state.memory.store(dummy_addr, sym_filename)

    # simulation_manager = simulation_manager.explore(find=target_func_addr)

    def check(state):
        if (state.ip.args[0] == target_func_addr):
            payload = rb'aaaabbbbccccdddq'

            arg0 = state.regs.x0
            arg1 = state.regs.x1

            filename_supplied = state.mem[arg0].with_type(angr.sim_type.SimTypeChar()).array(arg1)

            return state.satisfiable(extra_constraints=(
                arg1 == len(payload),
                *[filename_supplied[offset].resolved == byte for offset, byte in enumerate(payload)]))

            return True

        x0 = entry_calling_convention.cc.arg_locs(entry_calling_convention.prototype)[0].get_value(state) 
        x1 = entry_calling_convention.cc.arg_locs(entry_calling_convention.prototype)[1].get_value(state) 

        _x0 = state.solver.eval(state.regs.x0)
        _x1 = state.solver.eval(state.regs.x1)
        # Memory values offest from x0 are concretized to b'\x00' here. 
        # Try adjusting conretization strategy to keep memory regions around arguments
        # symbolic. E.g. SimConcretizationStrategyControlledData should do the trick. 
        
        return False
    
    simulation_manager = simulation_manager.explore(find=check)




    found = simulation_manager.found
    if len(found) > 0:
        print("Found path to target func!")
    else:
        print("Didn't find path to target func.")


if __name__ == "__main__":
    symbolic_filename()