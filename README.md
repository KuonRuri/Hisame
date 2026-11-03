# Hisame

Hisame is a coverage-guided fuzzer for OpenSBI's SBI interface on RV64 QEMU `virt` (single hart). An S-mode harness executes structured SBI calls while a host driver mutates inputs and records firmware execution coverage.

## Requirements

- Rust with the `riscv64gc-unknown-none-elf` target
- `qemu-system-riscv64`
- An OpenSBI `fw_dynamic` image

The default firmware path is `/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin`. Use `--qemu`, `--bios`, or `--harness` to specify different paths.

## Build and run

```sh
rustup target add riscv64gc-unknown-none-elf
./scripts/build.sh
./target/release/hisame fuzz --max-execs 100 --seed 1
```

Each run creates `output/run_.../`. `queue/` contains the initial cases and inputs that gained coverage; `findings/` contains saved failure candidates and replay results; `work/` contains the latest QEMU logs. `run.txt` records the configuration.

Replay a saved case with:

```sh
./target/release/hisame replay output/run_.../queue/id_000000.case --repeat 2
```

Run `./target/release/hisame --help` for all options. The default execution timeout is 3000 ms. Firmware coverage defaults to the physical address range `[0x80000000, 0x80200000)` and can be changed with `--firmware-start` and `--firmware-end`.

## Execution model

Each input contains up to eight SBI calls with extension and function IDs, six arguments per call, pointer flags, and a 4096-byte guest-memory buffer. The initial corpus covers SBI BASE functions, DBCN, PMU counter discovery, and short call sequences.

## DBTR target

Use the dedicated debug-trigger campaign with:

```sh
./scripts/build.sh
./target/release/hisame fuzz --target dbtr --max-execs 100 --seed 1
```

`--target dbtr` defaults to the structured generator. `--mutator legacy` and
`--mutator uniform` provide comparison strategies over the same DBTR seeds.
The driver first probes DBTR support and trigger count, then seeds trigger
discovery, shared-memory setup, read, install, update, enable, disable, and
uninstall paths. The harness reports the first 32 bytes of the input arena
after each DBTR call so the driver can check installed trigger indices.
`calls.csv` records every DBTR call result and its arena snapshot for analysis.
The target requires at least one trigger and at most 128, because its 4096-byte
arena must hold `trig_max * 32` bytes on RV64. The default QEMU/OpenSBI image
on this setup reports two triggers. Valid lifecycle cases use logical index 0 for
enable, disable, and uninstall; another implementation may assign a different
index. Each input runs in a fresh QEMU process.

Replay a DBTR case with `--target dbtr` to apply its contract checks:

```sh
./target/release/hisame replay output/run_.../queue/id_000007.case --target dbtr
```

The driver starts a fresh QEMU process for each input, loads the input into guest RAM at `0x88000000`, and runs the S-mode harness at `0x80200000`. It derives coverage from consecutive OpenSBI translation blocks within each firmware visit after the harness starts, ignoring firmware boot activity, and applies wall-clock and log-size limits. It records contract violations, guest traps, timeouts, and abnormal exits as failure candidates.

## Scope and limitations

Hisame targets RV64 QEMU `virt` with one hart and fixed guest load addresses.
The structured PMU generator assumes that firmware counter index 19 is usable
on the reference firmware. DBTR lifecycle cases assume that the first
installed logical trigger index is zero. Check these assumptions before using
a different firmware image.

Coverage consists of QEMU translation blocks and transitions, not source-level
branches. A saved failure candidate needs independent triage before it can be
attributed to a firmware defect.

## License

Hisame is licensed under the MIT License. See [LICENSE](LICENSE).
