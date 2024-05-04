from angrparc import *

from angr.sim_type import *
from angr import PointerWrapper

import unittest
from parameterized import parameterized

class TestTargetMethodAnalysis(unittest.TestCase):

    _filename_with_q = "my_file_with_q.txt"
    _filename_without_q = "my_file.txt"

    @parameterized.expand([
        [True],
        [False],
    ])
    def test_target_method_analysis_correctness(self, filename_has_q):
        """
        `./binaries/hello-rust` was compiled with the below functions.

        ```
        fn create_file_if_no_q(filename: &str) -> i32 {
            if filename.contains("q") { 
                return 1;
            }

            create_file(filename);
            return 0;
        }

        fn create_file(filename: &str) -> std::io::Result<()> {
            let mut file = fs::File::create(filename).expect("file creation should work");
            Ok(())
        }
        ```

        This analysis aims to determine whether or not it is possible to reach the
        standard library `std::File::create` function (target) from the function
        `create_file_if_no_q` (entry), and call it with various parameters, namely
        one filename _with_ the character "q", and one without.  
        """

        filename = None
        if filename_has_q:
            filename = TestTargetMethodAnalysis._filename_with_q
        else:
            filename = TestTargetMethodAnalysis._filename_without_q

        path = "./binaries/hello-rust"

        entry_func_addr = 0x100007020 # create_file_if_no_q
        target_func_addr = 0x100008bb4 # create_file

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
        target_func_prototype = SimTypeFunction(args = (charstar, longlong), returnty=None)

        def target_payload_satisfiability_check(state: SimState, target_arguments: List[Any]): 
            pointer = target_arguments[0]
            length = target_arguments[1]

            # If our string length can't be the desired length, we're unsat
            if not state.satisfiable(extra_constraints = (length == len(filename),)):
                return False

            symbolic_payload = state.mem[pointer].with_type(SimTypeChar()).array(len(filename))
            return state.satisfiable(extra_constraints=(
                length == len(filename), 
                *[symbolic_payload[offset].resolved == byte for offset, byte in enumerate(filename)],
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

        found_states = target_method_analysis.run()
        can_execute_target_with_filename = len(found_states) > 0
        assert can_execute_target_with_filename == (not filename_has_q)

if __name__ == "__main__":
    unittest.main()