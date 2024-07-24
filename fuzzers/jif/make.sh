set -e

export MACOSX_DEPLOYMENT_TARGET=10.14.0
export LIBAFL_EDGES_MAP_SIZE=3000000
                            #8888888

CLANG_FOLDER=`llvm-config --bindir`

cd libjif
cargo build --release

echo "[+] Setting up libAFL LLVM environment"

# if llvm dir doesnt exist, create it and copy stuff in
if [ ! -d "llvm" ]; then
    echo "[+] Creating LLVM dir"
    mkdir llvm
    cp -r $CLANG_FOLDER/../* llvm   
fi

# copy the libafl cc's in place to build chrome
rm -v llvm/bin/clang{,++}
cp -v target/release/libafl_cc llvm/bin/clang
cp -v target/release/libafl_cxx llvm/bin/clang++
cd -

# allow for symlinks
outdir="$(dirname "$(dirname "$PWD")")"/out/jif

# build jif
ninja -v -C "$outdir" jif
