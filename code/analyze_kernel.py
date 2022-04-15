import networkx as nx
import os
import subprocess
import shutil

##
# kernel_root = "/home/zhouhao/data_fast/android-kernel-4.9/out/common"
# bitcode_dir = "/home/zhouhao/data_fast/ASE-2021/kernel_analysis/bitcode"
##
kernel_root = "/home/zhouhao/data_fast/android-kernel-4.9/out/common"
bitcode_dir = "/home/zhouhao/data_fast/ASE-2021/kernel_analysis/bitcode"
##

#'''
## statistics
func = set()
for ll_file in os.listdir(bitcode_dir):
    if not ll_file.endswith(".dis"):
        continue
    
    ll_path = os.path.join(bitcode_dir, ll_file)
    
    fp = open(ll_path, "r")
    for line in fp.readlines():
        if line.startswith("define "):
            line = line.strip()
            func.add(line)
    fp.close()
print len(func)
exit()
#'''

'''
## P1. Build callgraph
## collect functions
function_set = set()
for cg_file in os.listdir(bitcode_dir):
    if not cg_file.endswith(".cg"):
        continue
    cg_path = os.path.join(bitcode_dir, cg_file)
    if not os.path.exists(cg_path):
        continue

    cg_fp = open(cg_path, "r")
    cg_lines = cg_fp.readlines()
    for line in cg_lines:
        line = line.strip()
        if not (("label=" in line) and ("{" in line)):
            continue
        name = line.split("{")[1].split("}")[0].split("|")[0].strip()
        function_set.add(name)
'''

'''
## find indirect function calls
structur2function = {} ## [structure] -> { [parameter_index] -> [function]s }
for dis_file in os.listdir(bitcode_dir):
    if not dis_file.endswith(".dis"):
        continue
    dis_path = os.path.join(bitcode_dir, dis_file)
    if not os.path.exists(dis_path):
        continue
    print dis_path
    
    ## collect declared structures
    structures = []
    dis_fp = open(dis_path, "r")
    for line in dis_fp.readlines():
        if not line.startswith("%struct."):
            continue
        if not (" = " in line):
            continue
        
        structure = line.split(" ")[0]
        if not (structure in structures):
            structures.append(structure)
            # print "  [Struct] " + structure
    dis_fp.close()

    ## resolve strucutre initializations
    dis_fp = open(dis_path, "r")
    for line in dis_fp.readlines():
        if not (" = " in line):
            continue
        if not (" { " in line):
            continue
        if not ("%struct." in line.split(" = ")[1].split(" { ")[0]):
            continue
        if " x " in line.split(" = ")[1].split(" { ")[0]:
            continue
        if ", section \"" in line:
            continue
            
        # cnt = 0 ## we have checked that only one element in "structures" can be matched
        for structure in structures:
            if (" " + structure + " ") in line.split("{ ")[0]:
                # cnt += 1
                # print "[Struct] " + structure
                # print line
                
                ## find the initialization body
                go_on = 0
                start_idx = line.find("{")
                end_idx = start_idx
                for char in line[start_idx:]:
                    if char == '{':
                        go_on += 1
                    if char == '}':
                        go_on -= 1
                    if go_on == 0:
                        break
                    end_idx += 1
                line = line[start_idx:(end_idx+1)] ## core part
                assert line[0] == '{'
                assert line[-1] == '}'
                line = line[1:-1].strip()
                # print line
                
                ## split the initialization body for each parameter/field
                parameters = []
                go_on = 0
                pstart_idx = 0
                pend_idx = pstart_idx
                for char in line:
                    if (char == '(') or (char == '[') or (char == '{'):
                        go_on += 1
                    if (char == ')') or (char == ']') or (char == '}'):
                        go_on -= 1
                    if (char == ',') and (go_on == 0):
                        p_line = line[pstart_idx:pend_idx].strip()
                        parameters.append(p_line)
                        # print "[parameter] " + p_line
                        pstart_idx = pend_idx + 1
                    pend_idx += 1
                p_line = line[pstart_idx:pend_idx].strip()
                parameters.append(p_line)
                # print "[parameter] " + p_line
                # print ""
                
                if not structur2function.has_key(structure):
                    structur2function[structure] = {}
                    for param_idx in range(len(parameters)):
                        structur2function[structure][param_idx] = []
                else:
                    assert len(structur2function[structure].keys()) == len(parameters)
                
                param_idx = 0
                for parameter in parameters:
                    if len(structur2function[structure][param_idx]) == 0:
                        structur2function[structure][param_idx] = []
                    function = parameter.split(" ")[-1]
                    if function.startswith("@"):
                        function = function[1:]
                        if function in function_set:
                            if not (function in structur2function[structure][param_idx]):
                                structur2function[structure][param_idx].append(function)
                    else:
                        pass
                    param_idx += 1
                break
        # assert (cnt == 0) or (cnt == 1)             
    dis_fp.close()
## output (Debug)
key_list = structur2function.keys()
key_list.sort()
for structure in key_list:
    for idx in range(len(structur2function[structure].keys())):
        for function in structur2function[structure][idx]:
            print "[%s] -> [%d] %s" % (structure, idx, function)

exit()
'''

'''
## build callgraph
function_calls = {} ## [function name] -> {[function name]s -> [so name]s}
for cg_file in os.listdir(bitcode_dir):
    if not cg_file.endswith(".cg"):
        continue
    cg_path = os.path.join(bitcode_dir, cg_file)
    if not os.path.exists(cg_path):
        continue
    
    ## parse "*.cg" files to get the function-call relationship
    idx2function = {} ## [function idx] -> [function name]
    cg_fp = open(cg_path, "r")
    cg_lines = cg_fp.readlines()
    ## fill in idx2function map
    for line in cg_lines:
        line = line.strip()
        if not (("label=" in line) and ("{" in line)):
            continue
        idx = line.split("[")[0].strip()
        name = line.split("{")[1].split("}")[0].split("|")[0].strip()
        # print "%s -> %s" % (idx, name)
        assert not idx2function.has_key(idx)
        idx2function[idx] = name
    ## fill in function_calls map
    for line in cg_lines:
        line = line.strip()
        if not (" -> " in line):
            continue
        src_idx = line.split(" -> ")[0].split(":")[0].strip()
        assert idx2function.has_key(src_idx)
        src_name = idx2function[src_idx]
        tgt_idx = line.split(" -> ")[1].split("[")[0].strip()
        assert idx2function.has_key(tgt_idx)
        tgt_name = idx2function[tgt_idx]
        
        if not function_calls.has_key(src_name):
            function_calls[src_name] = {}
        if not (tgt_name in function_calls[src_name].keys()):
            function_calls[src_name][tgt_name] = []
        if not (cg_file in function_calls[src_name][tgt_name]):
            function_calls[src_name][tgt_name].append(cg_file)
    cg_fp.close()

## output   
output = []
for function_src in function_calls.keys():
    for function_tgt in function_calls[function_src].keys():
        output.append(("%s ==>> %s\n" % (function_src, function_tgt)))
output.sort()

callgraph_fp = open("kernel_callgraph.txt", "w")
for outline in output:
    callgraph_fp.write(outline)
callgraph_fp.flush()
callgraph_fp.close()

cg_nx = nx.DiGraph()
for function_src in function_calls.keys():
    for function_tgt in function_calls[function_src].keys():
        label = str(function_calls[function_src][function_tgt])
        cg_nx.add_edge(function_src, function_tgt, label=label)
nx.write_gexf(cg_nx, "kernel_callgraph.gexf")

exit()
'''


## Load
function_calls = {} ## (function name) -> [function name]
callgraph_fp = open("kernel_callgraph.txt", "r")
for line in callgraph_fp.readlines():
    line = line.strip()
    function_src = line.split(" ==>> ")[0]
    function_tgt = line.split(" ==>> ")[1]
    if not function_calls.has_key(function_src):
        function_calls[function_src] = []
    if not (function_tgt in function_calls[function_src]):
        function_calls[function_src].append(function_tgt)
callgraph_fp.close()
print len(function_calls.keys())

cg_nx = nx.read_gexf("kernel_callgraph.gexf")

'''
## P2. Analyze callgraph
entrys = [""]
for entry in function_calls.keys():
    if entry.startswith("sys_") or entry.startswith("SyS_"):
        # print entry
        entrys.append(entry)

targets = ["__sock_create"]
for source in entrys:
    if not cg_nx.has_node(source):
        continue
    print "==>> %s" % (source)
    for target in targets:
        if not cg_nx.has_node(target):
            continue
        
        if nx.has_path(cg_nx, source, target):
            spath = nx.shortest_path(cg_nx, source, target)
            
            error = False
            ##  Filter-1:
            for path_function in spath:
                if "nl80211_set_wowlan" in path_function:
                    error = True
                    break
            
            if error == True:
                continue
            
            for path_function in spath:
                print "     %s" % (path_function)
            print "<<== %s" % (target)
'''      

