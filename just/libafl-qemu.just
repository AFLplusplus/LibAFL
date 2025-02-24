import "libafl.just"

export LIBAFL_QEMU_DIR_DEFAULT := BUILD_DIR / "qemu-libafl-bridge"
ARCH := env("ARCH", "x86_64")
DOTENV := source_directory() / "envs" / ".env." + ARCH
