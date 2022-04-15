SVFHOME="/home/zhouhao/SVF"
export LLVM_DIR="/home/zhouhao/LLVM/llvm-9.0.0.obj"
#export LLVM_DIR="/home/zhouhao/LLVM/llvm-11.0.0.obj"
export PATH=$LLVM_DIR/bin:$SVFHOME/Release-build/bin:$PATH

export PATH=$PATH:/home/zhouhao/whole-program-llvm
export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=/home/zhouhao/data_fast/android_0805/prebuilts/clang/host/linux-x86/clang-r353983c1/bin
#export LLVM_COMPILER_PATH=/home/zhouhao/data_fast/android_1005/prebuilts/clang/host/linux-x86/clang-r383902b/bin
export WLLVM_OUTPUT_LEVEL=DEBUG
