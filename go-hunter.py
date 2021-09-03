#searches for unsafe calls in the golang binaries
#@author ogre2007
#@category golang
#@keybinding
#@menupath
#@toolbar

import time
import json

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import PcodeOp

from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex

CGOCALL_PROFILE = {"inouts": [[0, 2], [1, 2], [1, 1], [2, 0], [1, 0]], 
        "adj": [[2, 3, 2, 2, 1], [2, 3, 2, 2, 1], [2, 3, 2, 2, 1], [2, 3, 2, 2, 1], [2, 3, 2, 2, 1]], 
         "calls": [[0, 0], [1, 0], [1, 1], [2, 1], [2, 3]],
         "count": 5
         }

def get_sizes(bbs):
    return [[x.getInSize(), x.getOutSize()] for x in bbs]
    
def bbs_size_filter(bbs1, bbs2): 
    return get_sizes(bbs1) == get_sizes(bbs2)
    
def get_outs(bb):
    return [bb.getOut(i) for i in range(0, bb.getOutSize())]    
    
def get_ins(bb):
    return [bb.getIn(i) for i in range(0, bb.getInSize())]
    
def get_adj_matrix(bbs):

    adj = list([[0]*len(bbs)] * len (bbs))
    
    for i, bb in enumerate(bbs, 0):
        ins = get_ins(bb)
        outs = get_outs(bb)
        for input in ins:
            adj[i][bbs.index(input)] += 1
        for out in outs:
            adj[i][bbs.index(out)] += 1
                
    #print(adj)
    return adj

def get_calls(bb):
    return [inst for inst in bb.getIterator() if inst.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL]
    
def get_calls_matrix(bbs):
    calls = [[bb.getIndex(),len(get_calls(bb))] for bb in bbs]
    return calls
    
def bbs_calls_filter(bbs1, bbs2):
    return get_calls_matrix(bbs1) == get_calls_matrix(bbs2)
    
def bbs_deep_filter(bbs1, bbs2):
    return get_adj_matrix(bbs1) == get_adj_matrix(bbs2)
    
def calc_depth(bbs):
    def recursive(bb, i, known_bbs, result):
        known_bbs.add(bb)
        result.append([bb.getIndex(), i])
        leafs = filter(lambda x: x not in known_bbs, get_outs(bb))
        for leaf in leafs:
            recursive(leaf, i + 1, known_bbs, result)
        
    root = bbs[0]
    known_bbs = {root}
    indexes = []
    recursive(root, 0, known_bbs, indexes)
    return sorted(indexes)

def get_calls_depth(bbs):
    depths = calc_depth(bbs)
    calls = get_calls_matrix(bbs)
    return [[depth[1], call[1]] for depth, call in zip(depths, calls)]

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

def compare_by_profile(profile, hf):
    if not hf:
        return False
    bbs = hf.getBasicBlocks()
    if profile["count"] != len(bbs): 
        return False
    print(hf.getFunction().getName())
    print(sorted(get_calls_depth(bbs)))
    if profile["calls"] != sorted(get_calls_depth(bbs)):
        return False
    print(profile["calls"])
    print(get_calls_depth(bbs))
    print(hf.getFunction().getName())
    return True
    
def decompile_all(fm, ab):
    start = time.time()
    fs = [func for func in fm.getFunctionsNoStubs(True)]
    hfs = [ab.get_high_function(func) for func in fs if func]
    print('Decompiled {} functions in {} seconds'.format(len(hfs),time.time()-start))
    return hfs

def known_function_get(fm, ab, address):
    func = fm.getFunctionAt(get_address(address))
    hf = ab.get_high_function(func)
    for bb in hf.getBasicBlocks():
        pass
        #print(bb.getType())
        #print('\n'.join(x.toString() for x in bb.getIterator()))

    bbs = hf.getBasicBlocks()
    
    profile = {"adj": get_adj_matrix(bbs),
                        "calls": sorted(get_calls_depth(bbs)),
                        "inouts": get_sizes(bbs),
                        "count": len(bbs)}
    
    return profile
    
    
if __name__ == '__main__':
    fm = currentProgram.getFunctionManager()
    ab = ASTBrowser()
    
    #
    #profile = known_function_get(fm, ab, 0x404da0)#0x13a10)
    #print(profile)
    hfs = decompile_all(fm, ab)
    start = time.time()
    hfs_filtered = filter(lambda x: compare_by_profile(CGOCALL_PROFILE, x), hfs)
    print('Filtered {} of {} in {} seconds'.format(len(hfs_filtered), len(hfs), time.time()-start))
    for hf in hfs_filtered:
        print(hf.getFunction().getName())