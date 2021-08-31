#searches for unsafe calls in the golang binaries
#@author ogre2007
#@category golang
#@keybinding
#@menupath
#@toolbar


from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import PcodeOp

# get ghidra's Address object from integer memory offset
def get_address(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    
    
class ASTBrowser(object):
    def __init__(self):
        options = DecompileOptions()
        self.monitor = ConsoleTaskMonitor()
        self.ifc = DecompInterface()
        self.ifc.setOptions(options)
        self.ifc.openProgram(getCurrentProgram())
    
    def get_high_function(self, func):
        # ifc.setSimplificationStyle("normalize") 
        res = self.ifc.decompileFunction(func, 60, monitor)
        high = res.getHighFunction()
        return high

def bb_get_calls(bb):
    # for op in bb.getIterator()
    return [op for op in bb.getIterator() if op.getOpcode() in {ghidra.program.model.pcode.PcodeOp.CALL}]


def calls_ineq(c1, c2, c3):
    try:
        a1, a2, a3 = c1.getInput(0).getAddress(), c2.getInput(0).getAddress(), c3.getInput(0).getAddress()
        return a1 != a2 and a1 != a3 and a2 != a3
    except Exception as e:
        raise e
        
def _check_block(bb, calls):
    if bb.getInSize() != 1 or bb.getOutSize() != 0:
        return False
    if not calls_ineq(*calls):
        return False
        
    # get parent bb
    pb = bb.getIn(0)
    
    if pb.getInSize() != 1 or pb.getOutSize() != 2:
        return False
        
    if pb.getIterator().next().getOpcode() != ghidra.program.model.pcode.PcodeOp.INT_NOTEQUAL:
        return False
        
    
    
    return True
    
    
class ASTComparer(object):
    def __init__(self):
        pass
    
    def is_runtime_cgocall(self, high_func):
        bbs = high_func.getBasicBlocks()
        bbs_len = len(bbs)
        if bbs_len != 5:
            return False
            
            
        for bb in bbs:
            calls = [op for op in bb.getIterator() if op.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL]

            #calls = [op for op in ops ]
            #print(calls)
            #print(ops)
            calls_count = len(calls)
            
            if calls_count > 3:
                break
            elif calls_count == 3:
                if _check_block(bb, calls):
                    return True
                break
            
        return False
        
        
if __name__ == '__main__':


    # == run examples =================================================================================
    # func = getGlobalFunctions("runtime.cgocall")[0]    # assumes only one function named `main`
    # get a FunctionManager reference for the current program
    fm = currentProgram.getFunctionManager()
    
    # initialize custom objects
    ab = ASTBrowser()
    ac = ASTComparer()
    func = fm.getFunctionAt(get_address(0x404da0))
    # get function object at memory virtual address
    
    for func in fm.getFunctionsNoStubs(True): #{func}:
        # lift function with decompiler
        hf = ab.get_high_function(func)
        if hf and ac.is_runtime_cgocall(hf):
            print(func.getName())