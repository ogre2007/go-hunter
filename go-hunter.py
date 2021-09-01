#searches for unsafe calls in the golang binaries
#@author ogre2007
#@category golang
#@keybinding
#@menupath
#@toolbar

import pickle
import marshal
import time

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import PcodeOp

from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex



def print_dg(digraph):
    print("DiGraph info:")
    edges = digraph.edgeIterator()
    while edges.hasNext():
        edge = edges.next()
        from_vertex = edge.from()
        to_vertex = edge.to()
        print("  Edge from {} to {}".format(from_vertex, to_vertex))

def child_comparison(dg1, dg2):
    def get_sizes(dg, v):
        return dg.getReferent(v).getInSize(), dg.getReferent(v).getOutSize()
    s1 = dg1.getSources()[0]
    s2 = dg2.getSources()[0]
    c1 = dg1.getChildren(s1)
    c2 = dg2.getChildren(s2)
    
    if len(c1) != len(c2):
        return False
    if get_sizes(dg1, s1) != get_sizes(dg2, s2):
        return False
    #print(c1)
    #print(c2)
    if set([get_sizes(dg1, x) for x in c1]) != set([get_sizes(dg2, x) for x in c2]):
        return False
    print([(dg1.getReferent(x).getInSize(), dg1.getReferent(x).getOutSize()) for x in c1])
    
    return True

def dg_comparison(dg1, dg2, vertex_func = None):
    for func in [DirectedGraph.numEdges, 
                        DirectedGraph.numVertices,
                        DirectedGraph.numSinks]:
        if func(dg1) != func(dg2):
            return False
    s1 = dg1.getSources()[0]
    s2 = dg2.getSources()[0]
    if dg1.degree(s1) != dg2.degree(s2):
        return False

    
    if not child_comparison(dg1, dg2):
        return False
    
    return True
        
def bbs_size_filter(bbs1, bbs2, vertex_func = None):
    def get_sizes_set(bbs):
        return [(x.getInSize(), x.getOutSize()) for x in bbs]
    
    return get_sizes_set(bbs1) == get_sizes_set(bbs2)
    

def bbs2graph(bbs):
    dg = DirectedGraph()
    for bb in bbs:
        
        v = Vertex(bb)
        dg.add(v)
        for i in range(0, bb.getOutSize()):
            vchild = Vertex(bb.getOut(i))
            if not dg.contains(vchild):
                dg.add(vchild)
            e = Edge(v, vchild)
            if not dg.contains(e):
                dg.add(e)
    return dg


def hfunc2graph(high_func):
    return bbs2graph(high_func.getBasicBlocks())


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
        try:
            high = res.getHighFunction()
            return high
        except AttributeError:
            return None
def calls_ineq(c1, c2, c3):
    try:
        a1, a2, a3 = c1.getInput(0).getAddress(), c2.getInput(0).getAddress(), c3.getInput(0).getAddress()
        return a1 != a2 and a1 != a3 and a2 != a3
    except Exception as e:
        raise e


def check_if_runtime_cgocall(bbs):
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
    bbs_len = len(bbs)
    if bbs_len != 5:
        return False
        
        
    for bb in bbs:
        calls = [op for op in bb.getIterator() if op.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL]
        calls_count = len(calls)
        
        if calls_count > 3:
            break
        elif calls_count == 3:
            if _check_block(bb, calls):
                return True
            break
    return False 

    
class ASTComparer(object):
    def __init__(self):
        pass
    
    def compare(self, high_func, comparer_func):
        bbs = high_func.getBasicBlocks()
        
        return comparer_func(bbs)


def find_by_bb_comparison(bbs, ab, fm):
    i = 1
    print(bbs)
    start = time.time()
    fs = [func for func in fm.getFunctionsNoStubs(True)]
    hfs = [ab.get_high_function(func) for func in fs if func]
    bbs_all = [x.getBasicBlocks() for x in hfs]
    print('Decompiled {} in {} seconds'.format(len(fs),time.time()-start))
    start = time.time()
    filtered = [bb for bb in bbs_all if bbs_size_filter(bbs, bb)]
    print('Filtered {} of {} in {} seconds'.format(len(filtered), len(bbs_all), time.time()-start))
    for fbbs in filtered:
        print(fbbs)
    
def find_by_graph_comparison(dg, ab, fm):
    i = 1
    print_dg(dg)
    
    for func in fm.getFunctionsNoStubs(True): 
        # lift function with decompiler
        hf = ab.get_high_function(func)
        if hf and dg_comparison(dg, hfunc2graph(hf)):
            print("{}:\t{}".format(i, func.getName()))
            #print('\n'.join(x.toString() for x in hf.getPcodeOps()))
            i += 1
            print_dg(hfunc2graph(hf))
            #break # implies that first found is target function
    

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
    hf = ab.get_high_function(func)
    for bb in hf.getBasicBlocks():
        print(bb.getType())
        print('\n'.join(x.toString() for x in bb.getIterator()))
        
        
    dg = hfunc2graph(hf)
    bbs = hf.getBasicBlocks()
    find_by_bb_comparison(bbs, ab, fm)
