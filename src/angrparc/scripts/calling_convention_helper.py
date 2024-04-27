from typing import List
from collections.abc import Iterable

import argparse
import angr

from angr.sim_type import SimTypeFunction
from angr.calling_conventions import SimFunctionArgument
from angr.analyses.cfg.cfg import CFG
from archinfo import Arch

class Result:
    def __init__(
        self,
        address: int,
        arch: Arch,
        prototype: SimTypeFunction,
        arg_locs: List[SimFunctionArgument]
    ):
        self.address = address
        self.arch = arch
        self.prototype = prototype
        self.arg_locs = arg_locs

    def display(self):
        print("Finished calling convention analysis for {address}".format(address = self.address))
        print("Architecture: {arch}".format(arch = self.arch.__repr__()))
        print("Function prototype: {prototype}".format(prototype = self.prototype.c_repr()))
        print("Function arguments: ")
        for arg in self.arg_locs:
            print("\t{arg}".format(arg = arg.__repr__()))
        print("\n")


def analyse_calling_conventions(project: angr.Project, addresses: List[int], cfg: CFG) -> Iterable[Result]:
    complete_calling_convention = project.analyses.CompleteCallingConventions(
        recover_variables=True,
        prioritize_func_addrs=addresses,
        skip_other_funcs=True,
        cfg=cfg,
        analyze_callsites=True)
    
    for address in addresses:
        function = complete_calling_convention.kb.functions.get_by_addr(address)
        arch = function.calling_convention.arch
        prototype = function.prototype
        arg_locs = function.calling_convention.arg_locs(prototype)
        yield Result(address, arch, prototype, arg_locs)


def main():
    parser = argparse.ArgumentParser(description='Guess a calling convention for a method of interest')
    parser.add_argument('-p', '--path',
                        type=str, 
                        required=True,
                        help='Path to binary')
    parser.add_argument('-a', '--address', 
                        action='append',
                        type=int,
                        required=True,
                        help='Function address')
    args = parser.parse_args()

    project = angr.Project(args.path, load_options={'auto_load_libs':False})
    cfg = project.analyses.CFG(fail_fast=True)
    # for address in args.address:
    #     result = analyse_calling_convention(project, address)
    #     result.display()
    results = analyse_calling_conventions(project, args.address, cfg)
    for result in results:
        result.display()


if __name__ == "__main__":
    main()