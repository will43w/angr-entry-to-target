from angr.analyses.cfg.cfg import CFG
from angr.exploration_techniques import Explorer

from target_method_model import TargetMethodModel

def get_explorer(
    target_address: int,
    target_method_model: TargetMethodModel,
    cfg: CFG
):
    def find(state):
        if (state.addr != target_address):
            return False
        
        return target_method_model.paylaod_is_satisfiable(state)
    
    target_node = cfg.model.get_any_node(target_address)
    def avoid(state):
        current_node = cfg.model.get_any_node(state.addr)
    
        if current_node is None:
            return False # TODO: What should be done here? What does `None` mean in this context?
        
        target_node_successors = cfg.model.get_all_successors(current_node)
        if target_node not in target_node_successors:
            return True
        
        return False
    
    return Explorer(find=find, avoid=avoid, cfg=cfg)


            