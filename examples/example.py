#!/usr/bin/env python

from angrparc import *

from angr.sim_type import *
from angr import PointerWrapper

import claripy

def symbolic_filename():
    path = "/Users/william.hafner/dev/hello-rust/target/debug/hello-rust"

    # objdump --syms /Users/william.hafner/dev/hello-rust/target/debug/hello-rust | grep "file"
    entry_func_addr = 4294996000
    target_func_addr = 4294996124

    charstar = SimTypePointer(SimTypeChar())
    longlong = SimTypeLongLong()
    
    # Setup of entry method model
    max_filename_size = 40 # max number of bytes we'll try to solve for
    symbolic_filename = claripy.BVS('symbolic_filename', 8 * max_filename_size)
    symbolic_filename_size = claripy.BVS("symbolic_filename_size", 64)
    
    filename_pointer = EntryFunctionArgument(
        type = charstar,
        value = PointerWrapper(symbolic_filename, buffer=True),
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
        arguments = (filename_pointer, filename_length),
        return_type = return_type
    )

    # Setup of target method model
    target_func_prototype = SimTypeFunction((charstar, longlong), longlong)

    payload = rb'_hello_world_with.txt'
    def target_payload_satisfiability_check(state: SimState, target_arguments: List[Any]): 
        pointer = target_arguments[0]
        length = target_arguments[1]

        # If our string length can't be the desired length, we're unsat
        if not state.satisfiable(extra_constraints = (length == len(payload),)):
            return False

        symbolic_payload = state.mem[pointer].with_type(SimTypeChar()).array(len(payload))
        return state.satisfiable(extra_constraints=(
            length == len(payload), 
            *[symbolic_payload[offset].resolved == byte for offset, byte in enumerate(payload)],
            )
        )
    
    target_function = TargetFunction(
        address = target_func_addr,
        prototype = target_func_prototype,
        satisfiability_check = target_payload_satisfiability_check)
    
    target_method_analysis = TargetMethodAnalysis(
        path,
        entry_function,
        target_function
    )

    found = target_method_analysis.run()
    if len(found) > 0:
        print("Success! Found payload to execute target as desired.")
    else:
        print("Failure! No payload found to execute target as desired.")


if __name__ == "__main__":
    symbolic_filename()