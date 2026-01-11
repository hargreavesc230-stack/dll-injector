# DLL Injector (Windows)

This project provides a minimal Windows DLL injector for **authorized** debugging,
testing, and research. It uses the classic `CreateRemoteThread` + `LoadLibraryW`
technique and is intentionally simple and transparent.

## Safety and Legal Notice

This tool is **only** for systems and software you own or have explicit written
permission to test. Do not use it to access, modify, or disrupt systems you do
not control. The authors and contributors are not responsible for misuse.

## Requirements

- Windows 10/11
- Rust toolchain (https://rustup.rs)
- A DLL that matches the target process architecture (x86 vs x64)

## Build

```
cargo build --release
```

## Usage

```
cargo run --release -- --dll C:\path\to\your.dll
```

The tool will list processes you can inject into with the required access rights,
prompt for a PID, and then perform the injection.

## Local test setup (sample target + test DLL)

1) Build the test DLL (cdylib):
   ```
   cargo build -p test-dll --release
   ```
   The DLL will be at `target\release\test_dll.dll` (crate names with hyphens build to underscores).

2) Run the sample target process that watches for a specific DLL name:
   ```
   cargo run -p sample-target --release -- --dll-name test_dll.dll
   ```
   It will print its PID and report once `test_dll.dll` is loaded.

3) In another shell, inject the built DLL into that PID:
   ```
   cargo run --release -- --dll target\release\test_dll.dll
   ```
   Choose the PID printed by `sample-target`. The target process will log when it
   detects the DLL.

## Notes

- The target process must be running under an account you can access.
- Cross-architecture injection (x86 -> x64 or x64 -> x86) will fail.
- Some protected processes cannot be opened without elevated privileges.

## License

MIT. See `LICENSE`.

## Anti-virus note

Because this tool includes DLL injection code, some security products may flag the built binaries as malware. Use only on systems you own or have permission to test.
