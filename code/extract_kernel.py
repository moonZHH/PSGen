import os
import subprocess
import shutil

##
# kernel_root = "/home/zhouhao/data_fast/android-kernel-4.9/out/common"
# bitcode_dir = "/home/zhouhao/data_fast/ASE-2021/kernel_analysis/bitcode"
##
kernel_root = "/home/zhouhao/data_fast/android-kernel-4.4/out/common"
bitcode_dir = "/home/zhouhao/data_fast/ASE-2021/kernel_analysis/bitcode"
##


#'''
## P1. Find all built-in.o files
obj_files = []
walker = os.walk(kernel_root)
for dir_path, dir_list, file_list in walker:
    for file_name in file_list:
        if not (file_name == "built-in.o"):
            continue
        file_path = os.path.join(dir_path, file_name)
        # print file_path
        
        if not (file_path in obj_files):
            obj_files.append(file_path)
# exit()
#'''

'''
## P2. extract-bc
for obj_file in obj_files:
    bc_name = obj_file.replace(kernel_root, "").replace("built-in.o", "")[1:][:-1].replace("/", "_") + ".bc"
    # print bc_name
    bc_path = os.path.join(bitcode_dir, bc_name)
    if not os.path.exists(os.path.dirname(bc_path)):
        os.makedirs(os.path.dirname(bc_path))
    
    # NOTE: it is possible that some built-in.o files may not have the ".llvm_bc" ELF section (should raraely happen?)
    command = "extract-bc --output %s %s" % (bc_path, obj_file)
    print "extrace-bc -> " + obj_file
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        # print line
exit()
'''

'''
## P3. llvm-dis
for bc_file in os.listdir(bitcode_dir):
    if not bc_file.endswith(".bc"):
        continue
    bc_path = os.path.join(bitcode_dir, bc_file)
    if not os.path.exists(bc_path):
        continue
    
    dis_path = bc_path.replace(".bc", ".dis")
    
    command = "llvm-dis %s -o=%s" % (bc_path, dis_path)
    print "llvm-dis -> " + bc_path
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        # print line
exit()
'''

#'''
## P4. SVF
for dis_file in os.listdir(bitcode_dir):
    if not dis_file.endswith(".dis"):
        continue
    dis_path = os.path.join(bitcode_dir, dis_file)
    if not os.path.exists(dis_path):
        continue
    
    cg_path = dis_path.replace(".dis", ".cg")
    svfg_path = dis_path.replace(".dis", ".svfg")
    if os.path.exists(cg_path) and os.path.exists(svfg_path):
        continue
    
    dis_size = round(os.path.getsize(dis_path) / float(1024 * 1024), 2)
    # if dis_size >= 36.0:
        # continue
    print "%s, %f" % (dis_path, dis_size)
    
    command = "wpa --ander --svfg --vcall-cha --dump-callgraph --dump-icfg --dump-inst --dump-svfg %s" % (dis_path)
    # print command
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        print line
        if "Aborted (core dumped)" in line:
            print "[ERROR] [ERROR] [ERROR] " + dis_path
    command = "sync"
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        print line
        
    ## move the generated callgraph_final.dot, svfg_final.dot, icfg_final.dot
    cg_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "callgraph_final.dot")
    cg_tgt = dis_path.replace(".dis", ".cg")
    if os.path.exists(cg_src):
        shutil.copy(cg_src, cg_tgt)
    svfg_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "svfg_final.dot")
    svfg_tgt = dis_path.replace(".dis", ".svfg")
    if os.path.exists(svfg_src):
        shutil.copy(svfg_src, svfg_tgt)
    icfg_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icfg_final.dot")
    icfg_tgt = dis_path.replace(".dis", ".icfg")
    if os.path.exists(icfg_src):
        shutil.copy(icfg_src, icfg_tgt)
    
    command = "sync"
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        print line
    command = "rm callgraph_*"
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        print line
    command = "rm svfg_*"
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        print line
    command = "rm icfg_*"
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        print line
    command = "sync"
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        line = line.strip()
        print line
exit()
#'''

## P5. callgraph
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
exit()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
