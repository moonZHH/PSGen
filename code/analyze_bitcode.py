import networkx as nx
import os
import re
import shutil
import subprocess
import Queue

##
aosp_out_dir = "/home/zhouhao/data_fast/android_1005/out/target/product/generic_x86"
bitcode_dir = "/home/zhouhao/data_fast/SECURITY-2021/native_analysis/bitcode_aosp_1005"
## Android 10
# aosp_out_dir = "/home/zhouhao/data_fast/android_0805/out/target/product/generic_x86"
# bitcode_dir = "/home/zhouhao/data_fast/SECURITY-2021/native_analysis/bitcode_aosp_0805"
## Android 9
# aosp_out_dir = "/home/zhouhao/data_fast/android_9/out/target/product/generic_x86"
# bitcode_dir = "/home/zhouhao/data_fast/SECURITY-2021/native_analysis/bitcode_aosp_9"

#### ==== #### PRE-PROCESS #### ==== ####

#'''
## STEP-1
soname2sopath = {} ## (so name) -> (so path)
soname2sopath_fp = open("soname2sopath.txt", "r")
for line in soname2sopath_fp.readlines():
    line = line.strip()
    so_name = line.split(" -> ")[0].strip()
    so_path = line.split(" -> ")[1].strip()
    assert not soname2sopath.has_key(so_name)
    soname2sopath[so_name] = so_path
soname2sopath_fp.close()

soname2depname = {} ## (so name) -> [dep so name]
soname2depname_fp = open("soname2depname.txt", "r")
for line in soname2depname_fp.readlines():
    line = line.strip()
    so_name = line.split(" -> ")[0].strip()
    if not soname2depname.has_key(so_name):
        soname2depname[so_name] = []
    so_dep = line.split(" -> ")[1].strip()
    soname2depname[so_name].append(so_dep)
soname2depname_fp.close()
#'''

#### ==== #### TEST #### ==== ####

'''
for so_name in soname2sopath.keys():
    so_path = soname2sopath[so_name]
    dis_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".dis"
    if not os.path.exists(dis_path):
        continue
    
    dis_fp = open(dis_path, "r")
    
    use_permission = False
    permissions = []
    has_ipermission = False
    #ipermissions = []
    
    for line in dis_fp.readlines():
        line = line.strip()
        if ".permission." in line:
            permission = line.split("\"")[1].split("\"")[0]
            if " " in permission:
                continue
            #if ".permission.DUMP" in line:
                #continue
            permissions.append(permission)
            use_permission = True
        if "IPermission" in line:
            #ipermissions.append(line)
            has_ipermission = True
    
    if (use_permission == True) and (has_ipermission == True):
        print "[ASM] %s" % (dis_path)
        for permission in permissions:
            print "    [1] %s" % (permission)
    
    dis_fp.close()
    
exit()
'''

#### ==== #### PROCESS #### ==== ####

so_tests = [] ## so name for the native libraray under test

#'''
## Process-1: find the native functions that use permission string constants
function2permission = {} ## [function name] -> { [permission] -> [function name]s }
for so_name in soname2sopath.keys():
    if len(so_tests) > 0 and not (so_name in so_tests):
        continue

    so_path = soname2sopath[so_name]
    
    svfg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".svfg"
    if not os.path.exists(svfg_path):
        continue
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    if not os.path.exists(cg_path):
        continue
    print "[Process-1-a]" + " " + so_path
    
    ## s1. parse "*.cg" files to get the function-call relationship
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    assert os.path.exists(cg_path)
    
    idx2function = {} ## (function idx) -> (function name)
    function_calls = {} ## (function name) -> [function name]
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
            function_calls[src_name] = []
        if not (tgt_name in function_calls[src_name]):
            function_calls[src_name].append(tgt_name)
    cg_fp.close()
    
    ## s2. parse "*.dis" files to find the permission variable
    dis_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".dis"
    assert os.path.exists(dis_path)
    
    strv2perm = {} ## (string variable) -> (permission string)
    perv2strv = {} ## (permission variable) -> (string variable)
    
    string_vars = []
    dis_fp = open(dis_path, "r")
    for line in dis_fp.readlines():
        line = line.strip()
        if ("\"android.permission." in line) and not(" " in line.split("\"")[1].split("\"")[0]):
            # print "[LINE][Permision] " + line
            string_var = line.split(" = ")[0]
            if not (string_var in string_vars):
                # print "[VAR][String] " + string_var
                string_vars.append(string_var)
                permission_name = line.split("\"")[1].replace("\\00", "")
                # print permission_name
                strv2perm[string_var] = permission_name
    dis_fp.close()
    
    permission_gvars = [] ## permission strings are global variables
    permission_lvars = [] ## permission strings are local variables
    dis_fp = open(dis_path, "r")
    dis_lines = dis_fp.readlines()
    for line in dis_lines:
        line = line.strip()
        if "StringPrintf" in line:
            continue
        
        for string_var in string_vars:
            if (("%s," % (string_var)) in line) or (("%s)" % (string_var)) in line):
                if ("call void" in line) and (line.count("@") >= 3): ## for global variables
                    # print "[LINE][Global] " + line
                    permission_var = line.split("@")[2].split(",")[0]
                    if not (permission_var in permission_gvars):
                        # print "[VAR][Permission] " + permission_var
                        permission_gvars.append(permission_var)
                        perv2strv[permission_var] = string_var
                    break
                elif ("call void" in line) and (line.count("%") >= 2): ## for local variables
                    # print "[LINE][Local1] " + line
                    permission_var = string_var
                    if not (permission_var in permission_lvars):
                        # print "[VAR][Permission] " + permission_var
                        permission_lvars.append(permission_var)
                        perv2strv[permission_var] = string_var
                    break
                elif ("tail call" in line) and ("setTo" in line) and (line.count("%") >= 2): ## for local variables
                    # print "[LINE][Local2] " + line
                    permission_var = string_var
                    if not (permission_var in permission_lvars):
                        # print "[VAR][Permission] " + permission_var
                        permission_lvars.append(permission_var)
                        perv2strv[permission_var] = string_var
                    break
                else:
                    # print "[LINE][Unknown] " + line
                    pass
    dis_fp.close()
    
    for gvar in permission_gvars:
        print "[Global] %s" % (gvar)
        pass
    for lvar in permission_lvars:
        print "[Local] %s" % (lvar)
        pass
    
    ## s3. parse "*.svfg" files to find ...
    svfg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".svfg"
    assert os.path.exists(svfg_path)
    
    func2perv = {} ## (function name) -> { (permission variable) -> [consumer function name] }
    
    #
    ## handle global variables
    svfg_fp = open(svfg_path, "r")
    svfg_lines = svfg_fp.readlines()
    for line in svfg_lines:
        line = line.strip()
        if not (" Glob " in line):
            continue
        if not ("|" in line):
            continue
        
        for permission_var in permission_gvars:
            if ("%s " % (permission_var)) in line:
                # print line
                
                use_functions = []
                assert "<--" in line
                lv_ptr = line.split("<--")[1].split("\\n")[0]
                for search_line in svfg_lines:
                    search_line = search_line.strip()
                    if not ("pts\\{" in search_line):
                        continue
                    if ((" %s " % (lv_ptr)) in search_line) or (("{%s " % (lv_ptr)) in search_line):
                        if "Fun[" in search_line:
                            use_function = search_line.split("Fun[")[1].split("]")[0]
                            if not (use_function in use_functions):
                                use_functions.append(use_function)
                
                flows = []
                for element in line.split("|"):
                    if not (">" in element):
                        continue
                    element = element.split("}")[0]
                    flow_idx = element.split(">")[1]
                    if not (flow_idx in flows):
                        flows.append(flow_idx)
                
                ## search each recoreded flow index in the "*.svfg" file
                for flow_idx in flows:
                    in_function = None ## each flow has a unique in_function
                    
                    for search_line in svfg_lines:
                        search_line = search_line.strip()
                        if not ("|" in search_line):
                            continue
                        if ((">%s|" % (flow_idx)) in search_line) or ((">%s}" % (flow_idx)) in search_line):
                            if "Fun[" in search_line:
                                new_in_function = search_line.split("Fun[")[1].split("]")[0]
                                if new_in_function.startswith("_GLOBAL_"):
                                    continue
                                if in_function != None:
                                    assert new_in_function == in_function
                                else:
                                    in_function = new_in_function
                
                    if in_function != None:
                        # print in_function
                        # print use_functions
                        if not func2perv.has_key(in_function):
                            func2perv[in_function] = {}
                        if not func2perv[in_function].has_key(permission_var):
                            func2perv[in_function][permission_var] = []
                        for use_function in use_functions:
                            if not (use_function in function_calls[in_function]):
                                continue
                            if not (use_function in func2perv[in_function][permission_var]):
                                func2perv[in_function][permission_var].append(use_function)
    svfg_fp.close()
    #
    
    #
    ## handle local variables
    svfg_fp = open(svfg_path, "r")
    svfg_lines = svfg_fp.readlines()
    for line in svfg_lines:
        line = line.strip()
        if not ("|" in line):
            continue
        
        for permission_var in permission_lvars:
            in_function = None
            use_functions = []
        
            if ("%s," % (permission_var)) in line:
                # print line
                ig_flows = set() ## storing the index of flow, which has already been handled
                lv_flows = Queue.Queue()
                for element in line.split("|"):
                    if not (">" in element):
                        continue
                    element = element.split("}")[0]
                    flow_idx = element.split(">")[1]
                    if not (flow_idx in lv_flows.queue):
                        # print flow_idx
                        lv_flows.put(flow_idx)
                
                lv_ptrs = set()
                while not lv_flows.empty():
                    flow_idx = lv_flows.get()
                    if flow_idx in ig_flows:
                        continue
                    
                    ## search each recoreded flow index in the "*.svfg" file
                    for search_line in svfg_lines:
                        search_line = search_line.strip()
                        if not ("|" in search_line):
                            continue
                        if search_line == line:
                            continue
                        if ((">%s|" % (flow_idx)) in search_line) or ((">%s}" % (flow_idx)) in search_line): 
                            if "Fun[" in search_line:
                                new_in_function = search_line.split("Fun[")[1].split("]")[0]
                                if in_function != None:
                                    assert new_in_function == in_function
                                else:
                                    in_function = new_in_function
                            if (" = " in search_line) and (search_line.count("%") > 1):
                                assert "<--" in search_line
                                for element in search_line.split("|"):
                                    if not (">" in element):
                                        continue
                                    element = element.split("}")[0]
                                    new_idx = element.split(">")[1]
                                    if (not (new_idx in lv_flows.queue)) and (not (new_idx in ig_flows)):
                                        # print new_idx
                                        lv_flows.put(new_idx)
                                lv_ptr = search_line.split("\\<--")[0].split("\\n")[1]
                                lv_ptrs.add(lv_ptr)
                                lv_ptr = search_line.split("\\<--")[1].split("\\n")[0]
                                lv_ptrs.add(lv_ptr)
                                        
                    ig_flows.add(flow_idx)
                
                for lv_ptr in lv_ptrs:
                    for search_line in svfg_lines:
                        search_line = search_line.strip()
                        if ("pts\\{" in search_line):
                            if ((" %s " % (lv_ptr)) in search_line) or (("{%s " % (lv_ptr)) in search_line):
                                if "Fun[" in search_line:
                                    use_function = search_line.split("Fun[")[1].split("]")[0]
                                    if not (use_function in use_functions):
                                        use_functions.append(use_function)
                        if ("th arg " in search_line):
                            if ((" %s, " % (lv_ptr)) in search_line) or (("(%s, " % (lv_ptr)) in search_line):
                                use_function = search_line.split("th arg ")[1].split(" ")[0]
                                if not (use_function in use_functions):
                                        use_functions.append(use_function)
            
            if in_function != None:
                # print in_function
                # print use_functions
                if not func2perv.has_key(in_function):
                    func2perv[in_function] = {}
                if not func2perv[in_function].has_key(permission_var):
                    func2perv[in_function][permission_var] = []
                for use_function in use_functions:
                    if not (use_function in function_calls[in_function]):
                        continue
                    if not (use_function in func2perv[in_function][permission_var]):
                        func2perv[in_function][permission_var].append(use_function)
    svfg_fp.close()
    #
                
    ## output (Debug)
    for in_function in func2perv.keys():
        print "[FUNCTION] " + in_function
        for permission_var in func2perv[in_function].keys():
            string_var = perv2strv[permission_var]
            permission_name = strv2perm[string_var]
            for use_function in func2perv[in_function][permission_var]:
                print "  [PERMISSION] " + permission_name + "(" + permission_var + ")" + " ==>> " + use_function
                
                ## store the result
                if not function2permission.has_key(in_function):
                    function2permission[in_function] = {}
                if not function2permission[in_function].has_key(permission_name):
                    function2permission[in_function][permission_name] = []
                if not (use_function in function2permission[in_function][permission_name]):
                    function2permission[in_function][permission_name].append(use_function)

## s4: handle the special cases, in which we cannot find the permission string
for so_name in soname2sopath.keys():
    if len(so_tests) > 0 and not (so_name in so_tests):
        continue

    so_path = soname2sopath[so_name]
    
    svfg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".svfg"
    if not os.path.exists(svfg_path):
        continue
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    if not os.path.exists(cg_path):
        continue
    print "[Process-1-b]" + " " + so_path
    
    ## s1. parse "*.cg" files to get the function-call relationship
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    assert os.path.exists(cg_path)
    
    idx2function = {} ## (function idx) -> (function name)
    function_calls = {} ## (function name) -> [function name]
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
            function_calls[src_name] = []
        if not (tgt_name in function_calls[src_name]):
            function_calls[src_name].append(tgt_name)
    cg_fp.close()
    
    for in_function in function_calls.keys():
        if function2permission.has_key(in_function):
            continue
        if ("android" in in_function) and ("checkPermission" in in_function):
            continue
        if ("android" in in_function) and ("checkCallingPermission" in in_function):
            continue
        
        for use_function in function_calls[in_function]:
            if ("android" in use_function) and ("checkPermission" in use_function):
                function2permission[in_function] = {}
                function2permission[in_function]["unknow"] = []
                function2permission[in_function]["unknow"].append(use_function)
                break
            if ("android" in use_function) and ("checkCallingPermission" in use_function):
                function2permission[in_function] = {}
                function2permission[in_function]["unknow"] = []
                function2permission[in_function]["unknow"].append(use_function)
                break

## output
output = []
for in_function in function2permission.keys():
    if "10onTransact" in in_function:
        continue
    for permission_name in function2permission[in_function]:
        for use_function in function2permission[in_function][permission_name]:
            if ("android" in use_function) and ("checkPermission" in use_function):
                output.append("%s <- %s\n" % (in_function, permission_name))
                break
            if ("android" in use_function) and ("checkCallingPermission" in use_function):
                output.append("%s <- %s\n" % (in_function, permission_name))
                break
output.sort()

permission_fp = open("permissions.txt", "w")
for outline in output:
    permission_fp.write(outline)
permission_fp.flush()
permission_fp.close()

exit()
#'''

'''
## Process-2: find the native functions that call IPCThread::getCallingUid
function2uid = {} ## [function name] -> [uid]s
for so_name in soname2sopath.keys():
    if len(so_tests) > 0 and not (so_name in so_tests):
        continue

    so_path = soname2sopath[so_name]
    
    svfg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".svfg"
    if not os.path.exists(svfg_path):
        continue
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    if not os.path.exists(cg_path):
        continue
    print so_path
    
    ## s1. parse "*.cg" files to get the function-call relationship
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    assert os.path.exists(cg_path)
    
    idx2function = {} ## [function idx] -> [function name]
    function_calls = {} ## [function name] -> [function name]s
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
            function_calls[src_name] = []
        if not (tgt_name in function_calls[src_name]):
            function_calls[src_name].append(tgt_name)
    cg_fp.close()
    
    ## find the candidate native functions from the callgraph
    candidates = set()
    for src_name in function_calls.keys():
        for tgt_name in function_calls[src_name]:
            if ("getCallingUid" in tgt_name) and ("IPCThread" in tgt_name):
                ## ignore some cases
                if "8BpBinder" in src_name:
                    continue
                if "checkCallingPermission" in src_name:
                    continue
                if "getCallingUid" in src_name:
                    continue
                
                candidates.add(src_name)
                # print "[INFO] %s" % (src_name)
                break
    
    ## s2. parse "*.icfg" files to ...
    icfg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".icfg"
    assert os.path.exists(icfg_path)
    
    icfg_nx = nx.drawing.nx_agraph.read_dot(icfg_path)
    
    getuid_nodes = set()
    icmp_nodes = {} # node_idx -> uid
    switch_nodes = {} # node_idx -> set(uid)
    for node_idx in icfg_nx.nodes():
        node_label = icfg_nx.nodes[node_idx]['label']
        if ("IPCThread" in node_label) and ("getCallingUid" in node_label) and (not "hardware" in node_label) and ("Fun[" in node_label) and ("Entry(" in node_label):
            # print "%s -> %s" % (node_idx, node_label)
            getuid_nodes.add(node_idx)
        if ("icmp " in node_label) and ("%call" in node_label):
            # print node_label
            if " 0" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_ROOT"
            if " 1000" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_SYSTEM"
            if " 1001" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_RADIO"
            if " 1002" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_BLUETOOTH"
            if " 1003" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_GRAPHICS"
            if " 1004" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_INPUT"
            if " 1005" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_AUDIO"
            if " 1006" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_CAMERA"
            if " 1009" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_MOUNT"
            if " 1010" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_WIFI"
            if " 1013" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_MEDIA"
            if " 1041" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_AUDIOSERVER"
            if " 2000" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_SHELL"
            if " 10000" in node_label.split("%call")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                icmp_nodes[node_idx] = "AID_APP_START"
        if ("switch " in node_label) and (not "%switch " in node_label) and ("%call" in node_label):
            # print node_label
            if " 0," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_ROOT")
            if " 1000," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_SYSTEM")
            if " 1001," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_RADIO")
            if " 1002," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_BLUETOOTH")
            if " 1003," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_GRAPHICS")
            if " 1004," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_INPUT")
            if " 1005," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_AUDIO")
            if " 1006," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_CAMERA")
            if " 1009," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_MOUNT")
            if " 1010," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_WIFI")
            if " 1013," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_MEDIA")
            if " 1041," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_AUDIOSERVER")
            if " 2000," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_SHELL")
            if " 10000," in node_label.split("[")[1].strip():
                # print "%s -> %s" % (node_idx, node_label)
                if not switch_nodes.has_key(node_idx):
                    switch_nodes[node_idx] = set()
                switch_nodes[node_idx].add("AID_APP_START")
    
    candidate_entrys = set() # store the icfg entry-nodes for the candidate native functions
    candidate_exits = set() # store the icfg exit-nodes for the candidate native functions
    for candidate in candidates:
        for node_idx in icfg_nx.nodes():
            node_label = icfg_nx.nodes[node_idx]['label']
            if (("Fun[%s]" % (candidate)) in node_label) and ("Entry(" in node_label):
                # print "%s -> %s" % (node_idx, node_label)
                candidate_entrys.add(node_idx)
            if (("Fun[%s]" % (candidate)) in node_label) and ("Exit(" in node_label):
                # print "%s -> %s" % (node_idx, node_label)
                candidate_exits.add(node_idx)
    
    entry2call = {} # store the mapping between the entry and the call-node to "getCallingUid"
    for src_node in candidate_entrys:
        for tgt_node in getuid_nodes:
            if nx.has_path(icfg_nx, src_node, tgt_node):
                # print "%s -> %s" % (src_node, tgt_node) 
                spath = nx.shortest_path(icfg_nx, src_node, tgt_node)
                for node_idx in spath:
                    node_label = icfg_nx.nodes[node_idx]['label']
                    # print node_label
                
                if not entry2call.has_key(src_node):
                    entry2call[src_node] = spath[-2]
                else:
                    origin_node = entry2call[src_node]
                    current_node = spath[-2]
                    # print "%s, %s" % (origin_node, current_node)
                    assert current_node == origin_node
    
    for entry_node in entry2call.keys():
        print "[Entry] %s" % (icfg_nx.nodes[entry_node]['label'])
        candidate_name = icfg_nx.nodes[entry_node]['label'].split("Fun[")[1].split("]")[0].strip()
        
        ## find the corresponding exit-node
        exit_node = None
        for tmp_node in candidate_exits:
            node_label = icfg_nx.nodes[tmp_node]['label']
            if (("Fun[%s]") % (candidate_name)) in node_label:
                exit_node = tmp_node
                break
        assert exit_node != None
        
        src_node = entry2call[entry_node]
        
        var2uids = {} ## 
        var2length = {} ## 
        
        ## case-1 (icmp)
        for tgt_node in icmp_nodes.keys():
            if nx.has_path(icfg_nx, src_node, tgt_node):
                spath = nx.shortest_path(icfg_nx, src_node, tgt_node)
                if len(spath) > 16:
                    continue
                ignore_path = False
                for node_idx in spath:
                    node_label = icfg_nx.nodes[node_idx]['label']
                    if ("Entry(" in node_label) and ("Fun[" in node_label):
                        ignore_path = True
                        break
                    if ("Exit(" in node_label) and ("Fun[" in node_label):
                        ignore_path = True
                        break
                if ignore_path == True:
                    continue
                
                if nx.has_path(icfg_nx, tgt_node, exit_node):
                    epath = nx.shortest_path(icfg_nx, tgt_node, exit_node)
                    if (len(epath) > 16) and ((not "dump" in candidate_name) and (not "Dump" in candidate_name)):
                        # print "%d,    %s" % (len(epath), icfg_nx.nodes[epath[-1]]['label'])
                        continue
                    
                # print "%s -> %s" % (src_node, tgt_node)
                for node_idx in spath:
                    node_label = icfg_nx.nodes[node_idx]['label']
                    # print node_label
                
                node_label = icfg_nx.nodes[tgt_node]['label']
                var_name = "%call" + node_label.split("%call")[1].split(",")[0]
                
                if not var2uids.has_key(var_name):
                    var2uids[var_name] = set()
                var2uids[var_name].add(icmp_nodes[tgt_node])
                
                if not var2length.has_key(var_name):
                    var2length[var_name] = len(spath)
                if len(spath) < var2length[var_name]:
                    var2length[var_name] = len(spath)
                
        ## case-2 (switch)                
        for tgt_node in switch_nodes.keys():
            if nx.has_path(icfg_nx, src_node, tgt_node):
                spath = nx.shortest_path(icfg_nx, src_node, tgt_node)
                if len(spath) > 16:
                    continue
                ignore_path = False
                for node_idx in spath:
                    node_label = icfg_nx.nodes[node_idx]['label']
                    if ("Entry(" in node_label) and ("Fun[" in node_label):
                        ignore_path = True
                        break
                    if ("Exit(" in node_label) and ("Fun[" in node_label):
                        ignore_path = True
                        break
                if ignore_path == True:
                    continue
                
                if nx.has_path(icfg_nx, tgt_node, exit_node):
                    epath = nx.shortest_path(icfg_nx, tgt_node, exit_node)
                    if (len(epath) > 16) and ((not "dump" in candidate_name) and (not "Dump" in candidate_name)):
                        # print "%d,    %s" % (len(epath), icfg_nx.nodes[epath[-1]]['label'])
                        continue
                    
                # print "%s -> %s" % (src_node, tgt_node)
                for node_idx in spath:
                    node_label = icfg_nx.nodes[node_idx]['label']
                    # print node_label
                    
                node_label = icfg_nx.nodes[tgt_node]['label']
                var_name = "%call" + node_label.split("%call")[1].split(",")[0]
                
                if not var2uids.has_key(var_name):
                    var2uids[var_name] = set()
                for uid_str in switch_nodes[tgt_node]:
                    var2uids[var_name].add(uid_str)
                
                if not var2length.has_key(var_name):
                    var2length[var_name] = len(spath)
                if len(spath) < var2length[var_name]:
                    var2length[var_name] = len(spath)
        
        assert len(var2uids.keys()) == len(var2length.keys())
        
        if len(var2length.keys()) > 0:
            tgt_var = None
            tgt_length = 100
            for var_name in var2length.keys():
                var_length = var2length[var_name]
                if var_length < tgt_length:
                    tgt_length = var_length
                    tgt_var = var_name
                
            uids = var2uids[tgt_var]
            if not function2uid.has_key(candidate_name):
                function2uid[candidate_name] = set()
            for uid_name in uids:
                function2uid[candidate_name].add(uid_name)

    for function_name in function2uid.keys():
        # print "[FUNCTION] " + function_name
        for uid_name in function2uid[function_name]:
            # print "    [UID] " + uid_name
            pass

## output
uid_fp = open("uids.txt", "w")
for function_name in function2uid.keys():
    if "10onTransact" in function_name:
        continue
    for uid_name in function2uid[function_name]:
        uid_fp.write("%s <- %s\n" % (function_name, uid_name))
uid_fp.flush()
uid_fp.close()

exit()
'''

'''
## Process-3: build callgraph for the native layer of Android framework
## find the inheritance of the "Bn*" class
nbinder2service = {} ## (Bn* Binder class) -> [Service class]
for so_name in soname2sopath.keys():
    if len(so_tests) > 0 and not (so_name in so_tests):
        continue
    
    so_path = soname2sopath[so_name]
    dis_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".dis"
    if not os.path.exists(dis_path):
        continue
    print so_path
    
    dis_fp = open(dis_path, "r")
    dis_lines = dis_fp.readlines()
    for line in dis_lines:
        line = line.strip()
        if not line.startswith("%\"class.") or not (" = type " in line):
            continue
        if ("Bn" in line.split(" = ")[0]) or ("." in line.split(" = ")[0].split("class.")[1]):
           continue
        if ("Bn" not in line.split(" = ")[1]):
            continue
        
        service_name = line.split("\" = ")[0].split("class.")[1]
        # print service_name
        if "H2BConverter" in service_name:
            continue
        
        # print line ## TODO: Bug
        
        nbinder_name = None
        for element in line.split("\" = ")[1].split("{")[1].split("}")[0].split(","):
            if "\"struct." in element:
                continue
            if not ("::Bn" in element):
               continue
            # print "    " + element
            binder_name = element.split("class.")[1].split(".base")[0]
            if nbinder_name == None:
                nbinder_name = binder_name
            else:
                assert nbinder_name == binder_name
        
        if (nbinder_name == None):
            continue
        if not nbinder2service.has_key(nbinder_name):
            nbinder2service[nbinder_name] = []
        if not (service_name in nbinder2service[nbinder_name]):
            nbinder2service[nbinder_name].append(service_name)
    
    dis_fp.close()
    
## output (debug)
for nbinder_name in nbinder2service.keys():
    print "[Binder] %s" % (nbinder_name)
    for service_name in nbinder2service[nbinder_name]:
        print "  [Service] %s" % (service_name)
# exit()        
## output
output = []
for nbinder_name in nbinder2service.keys():
    for service_name in nbinder2service[nbinder_name]:
        output.append(("%s ==>> %s\n" % (nbinder_name, service_name)))
output.sort()

ipc_fp = open("ipc.txt", "w")
for outline in output:
    ipc_fp.write(outline)
ipc_fp.flush()
ipc_fp.close()

## collect functions
function_set = set()
for so_name in soname2sopath.keys():
    if len(so_tests) > 0 and not (so_name in so_tests):
        continue

    so_path = soname2sopath[so_name]
    
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    if not os.path.exists(cg_path):
        continue
    # print so_path

    cg_fp = open(cg_path, "r")
    cg_lines = cg_fp.readlines()
    for line in cg_lines:
        line = line.strip()
        if not (("label=" in line) and ("{" in line)):
            continue
        name = line.split("{")[1].split("}")[0].split("|")[0].strip()
        function_set.add(name)

## build callgraph
function_calls = {} ## [function name] -> {[function name]s -> [so name]s}
for so_name in soname2sopath.keys():
    if len(so_tests) > 0 and not (so_name in so_tests):
        continue

    so_path = soname2sopath[so_name]
    
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    if not os.path.exists(cg_path):
        continue
    print so_path
    
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
            if ("10onTransact" in src_name):
                ## break callgraph edges
                continue
            elif ("android_os_BinderProxy" in src_name):
                ## break callgraph edges
                continue
            elif ("8transact" in tgt_name):
                ## break callgraph edges
                continue
            elif ("Bp" in src_name) and (re.search(r'(\d+)Bp(\S+)(\d+)', src_name) != None):
                ## manually insert callgraph edges
                for nbinder in nbinder2service.keys():
                    nbinder_name = ""
                    for element in nbinder.split("::"):
                        if element.startswith("Bn"):
                            element = "Bp" + element[2:]
                        nbinder_name += "%d%s" % (len(element), element)
                    if not (nbinder_name in src_name):
                        continue
                    for service in nbinder2service[nbinder]:
                        service_name = ""
                        for element in service.split("::"):
                            service_name += "%d%s" % (len(element), element)
                            tgt_name = src_name.replace(nbinder_name, service_name)
                            if tgt_name in function_set:
                                ## since we adjust tgt_name, we re-check it again
                                if not (tgt_name in function_calls[src_name].keys()):
                                    function_calls[src_name][tgt_name] = []
                continue
            else:
                ## normal cases
                function_calls[src_name][tgt_name] = []
        if not (so_name in function_calls[src_name][tgt_name]):
            function_calls[src_name][tgt_name].append(so_name)
    cg_fp.close()
    
## remove invalid callgraph edges
## NOTE: we assume that the edges with a common source function should share the same libraries
for source in function_calls.keys():
    libs = set()
    for target in function_calls[source].keys():
        for lib in function_calls[source][target]:
            libs.add(lib)
    remove_set = set()
    for target in function_calls[source].keys():
        if len(function_calls[source][target]) != len(libs):
            remove_set.add(target)
        for lib in libs:
            if not (lib in function_calls[source][target]):
                remove_set.add(target)
                break
    for remove_tgt in remove_set:
        del function_calls[source][remove_tgt]

## output
output = []
for function_src in function_calls.keys():
    for function_tgt in function_calls[function_src].keys():
        output.append(("%s ==>> %s\n" % (function_src, function_tgt)))
output.sort()

callgraph_fp = open("callgraph.txt", "w")
for outline in output:
    callgraph_fp.write(outline)
callgraph_fp.flush()
callgraph_fp.close()

cg_nx = nx.DiGraph()
for function_src in function_calls.keys():
    for function_tgt in function_calls[function_src].keys():
        label = str(function_calls[function_src][function_tgt])
        cg_nx.add_edge(function_src, function_tgt, label=label)
nx.write_gexf(cg_nx, "callgraph.gexf")

exit()
'''

#### ==== #### ANALYSIS #### ==== ####

bn2services = {} ## (binder class) -> [service class]
ipc_fp = open("ipc.txt", "r")
for line in ipc_fp.readlines():
    line = line.strip()
    bn_class = line.split(" ==>> ")[0]
    sv_class = line.split(" ==>> ")[1]
    if not bn2services.has_key(bn_class):
        bn2services[bn_class] = []
    if not (sv_class in bn2services[bn_class]):
        bn2services[bn_class].append(sv_class)
ipc_fp.close()

function2permissions = {} ## (function name) -> [permission name]
permission_fp = open("permissions.txt", "r")
for line in permission_fp.readlines():
    line = line.strip()
    function_name = line.split(" <- ")[0]
    permission_name = line.split(" <- ")[1]
    if not function2permissions.has_key(function_name):
        function2permissions[function_name] = []
    if not (permission_name in function2permissions[function_name]):
        function2permissions[function_name].append(permission_name)
permission_fp.close()

function_calls = {} ## (function name) -> [function name]
callgraph_fp = open("callgraph.txt", "r")
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

cg_nx = nx.read_gexf("callgraph.gexf")

'''
## Analysis-1 (explicit permission-check for NDK):
## collect entry functions
entrys = []
entrys_rm = []

so_ndk = [
           "libaaudio.so",
           # "libamidi.so",
           "libandroid.so",
           # "libbinder_ndk.so",
           "libc.so",
           "libcamera2ndk.so",
           "libjnigraphics.so",
           "libmediandk.so",
           "libnativewindow.so",
           "libneuralnetworks.so",
         ]
for so_name in so_ndk:
    so_path = soname2sopath[so_name]
    
    # command = "llvm-objdump --syms %s" % (so_path)
    command = "objdump -T %s" % (so_path)
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        if not (".text" in line):
            continue
        if ".hidden" in line:
            continue
        # print line
        entry = line.split(" ")[-1]
        if "." in entry:
            continue
        if entry in entrys_rm:
            continue
        
        if not (entry in entrys):
            print "  " + entry
            entrys.append(entry)
        else:
            # print "[WARN]: remove " + entry 
            entrys.remove(entry)
            entrys_rm.append(entry)

entrys.sort()
# for entry in entrys:
    # print entry

## for permission-guarded JNI function
src2tgt4permission = {} ## [JNI method] -> ([function name], path)
for source in entrys:
    if not cg_nx.has_node(source):
        continue
    # print "==>> %s" % (source)
    for target in function2permissions.keys():
        if not cg_nx.has_node(target):
            continue
        
        if nx.has_path(cg_nx, source, target):
            # print "<<== %s" % (target)
            
            ## Filter-1
            bp_cnt = 0
            spath = nx.shortest_path(cg_nx, source, target)
            # (a)
            if len(spath) >= 8:
                continue
            # (b)
            for path_node in spath:
                # print "    " + path_node
                if ("Bp" in path_node) and (re.search(r'(\d+)Bp(\S+)(\d+)', path_node) != None):
                    bp_cnt += 1
            if bp_cnt > 1:
                continue
            ## Filter-2
            is_constructor = False
            last_node = spath[-1]
            command = "c++filt %s" % (last_node)
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in p.stdout.readlines():
                line = line.replace("\n", "")
                if ("(" in line) and ("::" in line):
                    elements = line.split("(")[0].split("::")
                    if (len(elements) >= 3) and (elements[-1] == elements[-2]):
                        is_constructor = True
            if is_constructor == True:
                continue
            
            if not src2tgt4permission.has_key(source):
                src2tgt4permission[source] = []
            if not (target in src2tgt4permission[source]):
                src2tgt4permission[source].append((target, spath))

## output (Debug)
for jni_method in src2tgt4permission.keys():
    print "[SRC] %s" % (jni_method)
    path_idx = 0
    for (_, spath) in src2tgt4permission[jni_method]:
        for path_function in spath:
            print ("  [Path-%d] %s" % (path_idx, path_function))
        path_idx += 1    
        
    permissions = set()
    for permission_function,_ in src2tgt4permission[jni_method]:
        for permission in function2permissions[permission_function]:
            permissions.add(permission)
    # print "[JNI] %s" % (jni_method)
    for permission in permissions:
        print "  [Permission] %s" % (permission)

## overal results
ac_functions = set()
for jni_method in src2tgt4permission.keys():
    ac_functions.add(jni_method)
print len(ac_functions)

exit()
'''

#'''
## Analysis-2 (explicit permission-check for Binder):
## collect entry functions
entrys = []

for so_name in soname2sopath.keys():
    # if len(so_tests) > 0 and not (so_name in so_tests):
        # continue

    so_path = soname2sopath[so_name]
    if not ("camera" in so_path):
        continue
    
    svfg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".svfg"
    if not os.path.exists(svfg_path):
        continue
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    if not os.path.exists(cg_path):
        continue
    # print "[Analysis-2]" + " " + so_path
    
    ## s1. parse "*.cg" files to get the function-call relationship
    cg_path = so_path.replace(aosp_out_dir, bitcode_dir) + ".cg"
    assert os.path.exists(cg_path)
    
    idx2function = {} ## (function idx) -> (function name)
    function_calls = {} ## (function name) -> [function name]
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
            function_calls[src_name] = []
        if not (tgt_name in function_calls[src_name]):
            function_calls[src_name].append(tgt_name)
    cg_fp.close()
    
    for caller in function_calls.keys():
        if not ("10onTransact" in caller):
            continue
        if "7BBinder" in caller:
            continue
        
        # re_result = re.search(r'(\d+)Bn(\D+)(\d+)', caller)
        # if re_result == None:
            # continue
        # re_result = re.search(r'Bn(\D+)', re_result.group(0))
        # bn_class = re_result.group(0)
        
        bn_class = ""
        command = "c++filt %s" % (caller)
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            line = line.replace("\n", "")
            bn_class = line.split("(")[0].split(" ")[-1].replace("<", "").replace(">", "").replace("::onTransact", "")
        
        if not bn2services.has_key(bn_class):
            # print "[F] " + bn_class
            continue
        else:
            # print "[T] " + bn_class
            pass
        
        for sv_class in bn2services[bn_class]:
            for callee in function_calls[caller]:
                if "3net6BpNetd" in callee:
                    callee = callee.replace("3net6BpNetd", "3net17NetdNativeService")
                if "8hardware15BnCameraService" in callee:
                    callee = callee.replace("8hardware15BnCameraService", "13CameraService")
                
                command = "c++filt %s" % (callee)
                p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in p.stdout.readlines():
                    line = line.replace("\n", "")
                    if (sv_class in line) and not (callee in entrys):
                        entrys.append(callee)
                        break
entrys.sort()
# for entry in entrys:
    # print entry

## for permission-guarded JNI function
src2tgt4permission = {} ## [JNI method] -> ([function name], path)
for source in entrys:
    if not cg_nx.has_node(source):
        continue
    # print "==>> %s" % (source)
    for target in function2permissions.keys():
        if not cg_nx.has_node(target):
            continue
        
        if nx.has_path(cg_nx, source, target):
            # print "<<== %s" % (target)           
            
            ## Filter-1
            bp_cnt = 0
            spath = nx.shortest_path(cg_nx, source, target)
            ## (a)
            if len(spath) >= 8:
                continue
            ## (b)
            for path_node in spath:
                # print "    " + path_node
                if ("Bp" in path_node) and (re.search(r'(\d+)Bp(\S+)(\d+)', path_node) != None):
                    bp_cnt += 1
            if bp_cnt > 1:
                continue
            ## Filter-2
            is_constructor = False
            last_node = spath[-1]
            command = "c++filt %s" % (last_node)
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in p.stdout.readlines():
                line = line.replace("\n", "")
                if ("(" in line) and ("::" in line):
                    elements = line.split("(")[0].split("::")
                    if (len(elements) >= 3) and (elements[-1] == elements[-2]):
                        is_constructor = True
            if is_constructor == True:
                continue
            
            if not src2tgt4permission.has_key(source):
                src2tgt4permission[source] = []
            if not (target in src2tgt4permission[source]):
                src2tgt4permission[source].append((target, spath))

## output (Debug)
for jni_method in src2tgt4permission.keys():
    print "[SRC] %s" % (jni_method)
    path_idx = 0
    for (_, spath) in src2tgt4permission[jni_method]:
        for path_function in spath:
            print ("  [Path-%d] %s" % (path_idx, path_function))
        path_idx += 1    
        
    permissions = set()
    for permission_function,_ in src2tgt4permission[jni_method]:
        for permission in function2permissions[permission_function]:
            permissions.add(permission)
    # print "[JNI] %s" % (jni_method)
    for permission in permissions:
        print "  [Permission] %s" % (permission)

## overal results
ac_functions = set()
for jni_method in src2tgt4permission.keys():
    ac_functions.add(jni_method)
print len(ac_functions)

exit()
#'''

'''
## Analysis-3 (implicit permission-check for NDK):

function2permissions = {}
function2permissions["socket"] = []
function2permissions["socket"].append("android.permission.INTERNET")
function2permissions["socketpair"] = []
function2permissions["socketpair"].append("android.permission.INTERNET")

## collect entry functions
entrys = []
entrys_rm = []

so_ndk = [
           "libaaudio.so",
           "libamidi.so",
           "libandroid.so",
           "libbinder_ndk.so",
           "libc.so",
           "libcamera2ndk.so",
           "libjnigraphics.so",
           "libmediandk.so",
           "libnativewindow.so",
           "libneuralnetworks.so",
         ]
for so_name in so_ndk:
    print so_name

    if not soname2sopath.has_key(so_name):
        print "[WARN]: cannot find " + so_name
        continue

    so_path = soname2sopath[so_name]
    
    # command = "llvm-objdump --syms %s" % (so_path)
    command = "objdump -T %s" % (so_path)
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        if not (".text" in line):
            continue
        if ".hidden" in line:
            continue
        # print line
        entry = line.split(" ")[-1]
        if "." in entry:
            continue
        if entry in entrys_rm:
            continue
        
        if not (entry in entrys):
            print "  " + entry
            entrys.append(entry)
        else:
            # print "[WARN]: remove " + entry 
            entrys.remove(entry)
            entrys_rm.append(entry)

entrys.sort()
# for entry in entrys:
    # print entry

## for permission-guarded JNI function
src2tgt4permission = {} ## [JNI method] -> ([function name], path)
for source in entrys:
    if not cg_nx.has_node(source):
        continue
    # print "==>> %s" % (source)
    for target in function2permissions.keys():
        if not cg_nx.has_node(target):
            continue
        
        if nx.has_path(cg_nx, source, target):
            # print "<<== %s" % (target)
            
            ## Filter-1
            bp_cnt = 0
            spath = nx.shortest_path(cg_nx, source, target)
            for path_node in spath:
                # print "    " + path_node
                if ("Bp" in path_node) and (re.search(r'(\d+)Bp(\S+)(\d+)', path_node) != None):
                    bp_cnt += 1
            if bp_cnt > 1:
                continue
            ## Filter-2
            is_constructor = False
            last_node = spath[-1]
            command = "c++filt %s" % (last_node)
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in p.stdout.readlines():
                line = line.replace("\n", "")
                if ("(" in line) and ("::" in line):
                    elements = line.split("(")[0].split("::")
                    if (len(elements) >= 3) and (elements[-1] == elements[-2]):
                        is_constructor = True
            if is_constructor == True:
                continue
            ## Filter-3
            if len(spath) >= 2 and ("async_safe_write_log" in spath[-2] or "LogdWrite" in spath[-2]):
                continue
            
            if not src2tgt4permission.has_key(source):
                src2tgt4permission[source] = []
            if not (target in src2tgt4permission[source]):
                src2tgt4permission[source].append((target, spath))

## output (Debug)
for jni_method in src2tgt4permission.keys():
    print "[SRC] %s" % (jni_method)
    path_idx = 0
    for (_, spath) in src2tgt4permission[jni_method]:
        for path_function in spath:
            print ("  [Path-%d] %s" % (path_idx, path_function))
        path_idx += 1    
        
    permissions = set()
    for permission_function,_ in src2tgt4permission[jni_method]:
        for permission in function2permissions[permission_function]:
            permissions.add(permission)
    # print "[JNI] %s" % (jni_method)
    for permission in permissions:
        print "  [Permission] %s" % (permission)

## overal results
ac_functions = set()
for jni_method in src2tgt4permission.keys():
    ac_functions.add(jni_method)
print len(ac_functions)

exit()
'''

