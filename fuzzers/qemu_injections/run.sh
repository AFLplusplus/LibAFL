make static && { clear;cargo run -- -y injections.yaml -i in -o out -v  -- ./static 2>&1|tee foo; }
