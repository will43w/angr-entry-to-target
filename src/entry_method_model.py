from angr.sim_type import SimTypeFunction

class EntryMethodModel:
    def __init__(self, entry_method_prototype: SimTypeFunction):
        self.method_prototype = entry_method_prototype

    def generate_symbolic_arguments():
        raise NotImplementedError