export LD_LIBRARY_PATH=`pwd`
make && { clear;cargo run -- -y sql.yaml -i in -o out -v  -- ./sqltest 2>&1|tee foo; }
