import os

log_dir = "/home/zhouhao/data_fast/android_0105"
log_output = "/home/zhouhao/data_fast/ASE-2021/patch_framework/aosp_0105.log"

out_fp = open(log_output, 'w')

log_list = os.listdir(log_dir)
log_list.sort()
#print flist

for log_name in log_list:
    if not log_name.startswith("log"):
        continue
    print log_name
    
    log_path = os.path.join(log_dir, log_name)
    assert os.path.exists(log_path)
    
    in_fp = open(log_path, 'r')
    for line in in_fp.readlines():
        out_fp.write(line)
        pass
    in_fp.close()
    
out_fp.flush()
out_fp.close()    

