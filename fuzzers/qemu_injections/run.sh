make && { clear;cargo run -- -y sql.yaml -i in -o out -v  -- ./static 2>&1|tee foo; }
