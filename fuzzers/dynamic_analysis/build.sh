export CC=$(pwd)/target/release/libafl_cc
export CXX=$(pwd)/target/release/libafl_cxx
export CXXFLAGS='--libafl'
export CFLAGS='--libafl'
export LDFLAGS='--libafl'
export ANALYSIS_OUTPUT=`pwd`/analysis
cd Little-CMS
./autogen.sh
./configure


make -j $(nproc)

$CXX $CXXFLAGS ../cms_transform_fuzzer.cc -I include/ src/.libs/liblcms2.a -o ../fuzzer
