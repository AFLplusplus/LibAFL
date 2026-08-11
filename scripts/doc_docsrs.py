#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tomllib


def run_docsrs():
    # Resolve script directory to make it location-independent
    script_dir = os.path.dirname(os.path.realpath(__file__))
    root_dir = os.path.dirname(script_dir)
    os.chdir(root_dir)

    print("Running docs.rs simulation build across all packages...")

    metadata_proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(metadata_proc.stdout)
    packages = [
        p
        for p in data["packages"]
        if p.get("publish") is None or len(p.get("publish", [])) > 0
    ]
    packages.sort(key=lambda x: x["name"])

    failures = []
    successes = []

    for pkg_info in packages:
        pkg = pkg_info["name"]
        manifest_path = pkg_info["manifest_path"]

        with open(manifest_path, "rb") as f:
            manifest_data = tomllib.load(f)

        docs_rs = (
            manifest_data.get("package", {})
            .get("metadata", {})
            .get("docs", {})
            .get("rs", {})
        )

        cmd = ["cargo", "doc", "--no-deps", "-p", pkg]

        config_desc = []
        if docs_rs.get("no-default-features"):
            cmd.append("--no-default-features")
            config_desc.append("no-default")

        if docs_rs.get("all-features"):
            cmd.append("--all-features")
            config_desc.append("all-features")
        elif "features" in docs_rs:
            cmd.extend(["--features", ",".join(docs_rs["features"])])
            config_desc.append(f"features={docs_rs['features']}")
        else:
            cmd.append("--all-features")
            config_desc.append("default(all-features)")

        rustdoc_args = docs_rs.get("rustdoc-args", ["--cfg", "docsrs"])
        rustdocflags = " ".join(rustdoc_args) if rustdoc_args else "--cfg docsrs"

        cfg_str = ", ".join(config_desc)
        print(f"Documenting {pkg:<28} [{cfg_str}]")

        env = os.environ.copy()
        env["DOCS_RS"] = "1"
        if "RUSTDOCFLAGS" in env:
            env["RUSTDOCFLAGS"] = f"{env['RUSTDOCFLAGS']} {rustdocflags}"
        else:
            env["RUSTDOCFLAGS"] = rustdocflags

        res = subprocess.run(cmd, env=env, capture_output=True, text=True)

        if res.returncode == 0:
            successes.append(pkg)
        else:
            failures.append((pkg, cfg_str, res.stderr))
            print(f"FAILED to document {pkg}!")

    print("\n" + "=" * 80)
    print(
        f"DOCS.RS BUILD SUMMARY: {len(successes)} / {len(packages)} PASSED ({len(failures)} failed)"
    )
    if failures:
        print("=" * 80)
        for pkg, cfg_str, err in failures:
            print(f"\n--- ERROR IN {pkg} ({cfg_str}) ---")
            lines = [
                l
                for l in err.splitlines()
                if "error" in l.lower() or "panicked" in l.lower()
            ]
            print("\n".join(lines[:15]))
        sys.exit(1)


if __name__ == "__main__":
    run_docsrs()
