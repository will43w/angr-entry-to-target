#!/usr/bin/env python

import angr
import claripy

def symbolic_filename():
    def get_address_from_symbol(funcName: str):
        # Hack over find_symbol - see https://github.com/angr/cle/issues/194
        addrs = project.loader.find_all_symbols(funcName)
        for addr in addrs:
            return addr.rebased_addr

    project = angr.Project("/Users/william.hafner/dev/hello-rust/target/debug/hello-rust", load_options={'auto_load_libs':False})

    # objdump --syms /Users/william.hafner/dev/hello-rust/target/debug/hello-rust | grep "file"
    entry_func_addr = get_address_from_symbol('__ZN10hello_rust23rpc_create_file_if_no_q17h35276a1d9d36e04eE')
    target_func_addr = get_address_from_symbol('__ZN10hello_rust11create_file17h57d00ed4135b8bafE')

    charstar = angr.sim_type.SimTypePointer(angr.sim_type.SimTypeChar())
    longlong = angr.sim_type.SimTypeLongLong()
    entry_func_prototype = angr.sim_type.SimTypeFunction((charstar, longlong), longlong)
    target_func_prototype = angr.sim_type.SimTypeFunction((charstar, longlong), longlong)

    symbolic_input_generator = SymbolicInputGenerator(entry_calling_convention)
    symbolic_arguments = symbolic_input_generator.create_symbolic_input()

    cfg = project.analyses.CFG(fail_fast=True)
    entry_variable_recovery = project.analyses.VariableRecoveryFast(entry_func_addr) # Variable analysis required for calling convention analysis (?)
    entry_calling_convention = project.analyses.CallingConvention(entry_func_addr)

    state = project.factory.call_state(entry_func_addr, *symbolic_arguments, cc=entry_calling_convention.cc, prototype=entry_func_prototype) # provide prototype kwarg

    symbolic_input_generator.constrain_symbolic_input(symbolic_arguments)
    
    simulation_manager = project.factory.simulation_manager(state)

    payload = rb'_hello_world_with.txq'
    def target_satisfiability_check(symbolic_arguments, payload): # TODO: Make symbolic_arguments a List[ValueWithSymType] to avoid having to `.with_type`. Give this class some abstractions where you can pass in a state and get values
        arg0 = symbolic_arguments[0].get_value(state).concrete_value
        arg1 = symbolic_arguments[1].get_value(state)

        symbolic_payload = state.mem[arg0].with_type(angr.sim_type.SimTypeChar()).array(arg1)
        return state.satisfiable(extra_constraints=(
            arg1 == len(payload), 
            *[symbolic_payload[offset].resolved == byte for offset, byte in enumerate(payload)]))

    # Calling convention, variables, and variable types of target function
    # https://github.com/angr/angr/issues/3125
    target_variable_recovery = project.analyses.VariableRecoveryFast(target_func_addr) # Variable analysis required for calling convention analysis (?)
    target_calling_convention = project.analyses.CallingConvention(target_func_addr) # Discover registers used to store function arguments

    explorer = TargetMethodPayloadExecution.get_explorer(
        target_func_addr,
        target_method_model,
        cfg
    )

    simulation_manager.use_technique(explorer)

    found = simulation_manager.found
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