mod case;
mod dbtr;
mod runner;

use case::{
    ARENA_SIZE, BASE, DBCN, DBTR, InputCase, Mutator, PMU, Rng, initial_cases, mutate,
    structured_case, uniform_case,
};
use runner::{Edge, Outcome, RunResult, Runner};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const USAGE: &str = "Hisame: a small OpenSBI / QEMU virt SBI fuzzer
Usage:
  hisame fuzz [--max-execs N] [--duration-secs N] [--seed N] [--target NAME] [--mutator NAME] [common options]
  hisame replay CASE [--repeat N] [common options]
Common options:
  --qemu PATH             QEMU system emulator (default: qemu-system-riscv64)
  --bios PATH             OpenSBI firmware image
  --harness PATH          built RISC-V harness ELF
  --out DIR               output directory (default: output)
  --timeout-ms N          per-execution wall clock limit (default: 3000)
  --firmware-start N      coverage range start (default: 0x80000000)
  --firmware-end N        coverage range end, exclusive (default: 0x80200000)
  --mutator NAME          legacy, uniform, or structured (default: legacy; dbtr: structured)
  --target NAME           default or dbtr (default: default)
  --duration-secs N       stop fuzzing after approximately N seconds
  -h, --help              show this help
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Default,
    Dbtr,
}

impl Target {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "default" => Ok(Self::Default),
            "dbtr" => Ok(Self::Dbtr),
            _ => Err(format!("unknown target: {value}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Dbtr => "dbtr",
        }
    }
}

enum Mode {
    Fuzz {
        max_execs: usize,
        seed: u64,
        mutator: Mutator,
        duration: Option<Duration>,
    },
    Replay {
        case: PathBuf,
        repeat: usize,
    },
}

struct Options {
    mode: Mode,
    target: Target,
    runner: Runner,
    output: PathBuf,
}

fn parse_number(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        value.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn parse_options() -> Result<Option<Options>, String> {
    let mut args = env::args().skip(1);
    let command = match args.next() {
        Some(s) if s == "-h" || s == "--help" => return Ok(None),
        Some(s) => s,
        None => return Ok(None),
    };
    let mut qemu = PathBuf::from("qemu-system-riscv64");
    let mut bios = PathBuf::from("/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin");
    let mut harness = PathBuf::from("target/riscv64gc-unknown-none-elf/release/hisame-harness");
    let mut output = PathBuf::from("output");
    let mut timeout_ms = 3000u64;
    let mut firmware_start = 0x8000_0000u64;
    let mut firmware_end = 0x8020_0000u64;
    let mut max_execs = 100usize;
    let mut max_execs_set = false;
    let mut duration_secs = None;
    let mut mutator = Mutator::Legacy;
    let mut mutator_set = false;
    let mut target = Target::Default;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos() as u64;
    let mut repeat = 1usize;
    let mut case_path = None;
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(None);
        }
        if command == "replay" && case_path.is_none() && !arg.starts_with('-') {
            case_path = Some(PathBuf::from(arg));
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {arg}"))?;
        match arg.as_str() {
            "--qemu" => qemu = value.into(),
            "--bios" => bios = value.into(),
            "--harness" => harness = value.into(),
            "--out" => output = value.into(),
            "--timeout-ms" => timeout_ms = parse_number(&value)?,
            "--firmware-start" => firmware_start = parse_number(&value)?,
            "--firmware-end" => firmware_end = parse_number(&value)?,
            "--max-execs" => {
                max_execs = usize::try_from(parse_number(&value)?)
                    .map_err(|_| "execution count is too large")?;
                max_execs_set = true;
            }
            "--seed" => seed = parse_number(&value)?,
            "--mutator" => {
                mutator = Mutator::parse(&value)?;
                mutator_set = true;
            }
            "--target" => target = Target::parse(&value)?,
            "--duration-secs" => duration_secs = Some(parse_number(&value)?),
            "--repeat" => repeat = parse_number(&value)? as usize,
            _ => return Err(format!("unknown option: {arg}")),
        }
    }
    if timeout_ms == 0 || max_execs == 0 || repeat == 0 {
        return Err("timeout, execution count, and repeat count must be positive".into());
    }
    if duration_secs == Some(0) {
        return Err("duration must be positive".into());
    }
    if duration_secs.is_some() && !max_execs_set {
        max_execs = usize::MAX;
    }
    if target == Target::Dbtr && !mutator_set {
        mutator = Mutator::Structured;
    }
    let mode = match command.as_str() {
        "fuzz" => Mode::Fuzz {
            max_execs,
            seed,
            mutator,
            duration: duration_secs.map(Duration::from_secs),
        },
        "replay" => Mode::Replay {
            case: case_path.ok_or("replay requires a .case path")?,
            repeat,
        },
        _ => return Err(format!("unknown command: {command}")),
    };
    let runner = Runner {
        qemu,
        bios,
        harness,
        work_dir: output.join("work"),
        timeout: Duration::from_millis(timeout_ms),
        firmware_start,
        firmware_end,
    };
    Ok(Some(Options {
        mode,
        target,
        runner,
        output,
    }))
}

fn oracle_issue(case: &InputCase, run: &RunResult, target: Target) -> Option<String> {
    if run.outcome != Outcome::Completed {
        return None;
    }
    let mut pmu_counter_count = None;
    let mut dbtr_trigger_count = None;
    let mut dbtr_shmem_at_arena = false;
    for (i, (call, result)) in case.calls.iter().zip(&run.results).enumerate() {
        if call.eid == BASE && call.fid <= 6 && result.error != 0 {
            return Some(format!(
                "call {i}: required SBI BASE function failed: {}",
                result.error
            ));
        }
        if call.eid == DBCN && call.fid <= 1 && result.error == 0 && result.value > call.args[0] {
            return Some(format!(
                "call {i}: DBCN transferred more bytes than requested"
            ));
        }
        if call.eid == PMU && call.fid == 0 {
            if result.error != 0 {
                return Some(format!(
                    "call {i}: PMU counter count failed: {}",
                    result.error
                ));
            }
            pmu_counter_count = Some(result.value);
        }
        if call.eid == PMU && call.fid == 1 {
            if let Some(count) = pmu_counter_count {
                let expected_error = if call.args[0] < count { 0 } else { -3 };
                if result.error != expected_error {
                    return Some(format!(
                        "call {i}: PMU counter info index {} returned {}, expected {}",
                        call.args[0], result.error, expected_error
                    ));
                }
            }
        }
        if target == Target::Dbtr && call.eid == DBTR {
            if call.fid == 0 {
                if result.error != 0 {
                    return Some(format!(
                        "call {i}: DBTR trigger count failed: {}",
                        result.error
                    ));
                }
                if call.args[0] == 0 {
                    if let Some(old) = dbtr_trigger_count {
                        if old != result.value {
                            return Some(format!(
                                "call {i}: DBTR trigger count changed from {old} to {}",
                                result.value
                            ));
                        }
                    }
                    dbtr_trigger_count = Some(result.value);
                } else if dbtr_trigger_count.is_some_and(|max| result.value > max) {
                    return Some(format!("call {i}: DBTR matching triggers exceed total"));
                }
            }
            if call.fid == 1 && result.error == 0 {
                dbtr_shmem_at_arena = call.ptr_mask & 1 != 0
                    && call.args[0] == 0
                    && call.args[1] == 0
                    && call.args[2] == 0;
            }
            if call.fid == 3 && call.args[0] == 1 && result.error == 0 && dbtr_shmem_at_arena {
                if let (Some(max), Some(words)) = (dbtr_trigger_count, result.arena_words) {
                    if words[0] >= max {
                        return Some(format!(
                            "call {i}: installed DBTR index {} exceeds trigger count {max}",
                            words[0]
                        ));
                    }
                }
            }
        }
    }
    None
}

fn failure_signature(case: &InputCase, run: &RunResult, target: Target) -> Option<String> {
    if let Some(issue) = oracle_issue(case, run, target) {
        return Some(format!("oracle: {issue}"));
    }
    let call_context = case
        .calls
        .get(run.results.len())
        .map(|call| {
            format!(
                " at call {} eid={:#x} fid={}",
                run.results.len(),
                call.eid,
                call.fid
            )
        })
        .unwrap_or_default();
    match run.outcome {
        Outcome::Completed => None,
        Outcome::GuestTrap { cause, tval, pc } => Some(format!(
            "guest trap{call_context}: cause={cause:#x}, tval={tval:#x}, pc={pc:#x}"
        )),
        Outcome::TimedOut => Some(format!("wall-clock timeout{call_context}")),
        Outcome::OutputLimit => Some(format!("QEMU output exceeded the size limit{call_context}")),
        Outcome::AbnormalExit => Some(format!(
            "QEMU or guest exited without a complete result{call_context}"
        )),
    }
}

fn save_case(dir: &Path, name: &str, case: &InputCase) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{name}.case"));
    fs::write(&path, case.to_bytes(0)).map_err(|e| e.to_string())?;
    Ok(path)
}

fn outcome_name(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Completed => "completed",
        Outcome::GuestTrap { .. } => "guest_trap",
        Outcome::TimedOut => "timeout",
        Outcome::OutputLimit => "output_limit",
        Outcome::AbnormalExit => "abnormal_exit",
    }
}

fn fuzz(
    mut opts: Options,
    max_execs: usize,
    seed: u64,
    mutator: Mutator,
    duration: Option<Duration>,
) -> Result<(), String> {
    fs::create_dir_all(&opts.output).map_err(|e| e.to_string())?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let run_root = opts
        .output
        .join(format!("run_{stamp}_{}", std::process::id()));
    fs::create_dir(&run_root).map_err(|e| e.to_string())?;
    opts.output = run_root;
    opts.runner.work_dir = opts.output.join("work");
    opts.runner.validate()?;
    let mut dbtr_trigger_count = None;
    if opts.target == Target::Dbtr {
        let probe = InputCase {
            calls: vec![
                case::Call::new(BASE, 3, [DBTR, 0, 0, 0, 0, 0], 0),
                case::Call::new(DBTR, 0, [0; 6], 0),
            ],
            arena: [0; ARENA_SIZE],
        };
        let result = opts.runner.run(&probe, seed)?;
        if result.outcome != Outcome::Completed
            || result.results.len() != 2
            || result.results[0].error != 0
            || result.results[0].value == 0
            || result.results[1].error != 0
            || result.results[1].value == 0
        {
            return Err("DBTR is unavailable or has no triggers on this firmware".into());
        }
        if result.results[1].value > (ARENA_SIZE / 32) as u64 {
            return Err("DBTR shared memory exceeds the 4096-byte input arena".into());
        }
        dbtr_trigger_count = Some(result.results[1].value);
        println!("DBTR available: {} triggers", result.results[1].value);
    }
    let manifest = format!(
        "seed={seed:#x}\nmax_execs={max_execs}\ntarget={}\nmutator={}\ndbtr_triggers={}\nduration_secs={}\ntimeout_ms={}\nqemu={}\nbios={}\nharness={}\nfirmware_start={:#x}\nfirmware_end={:#x}\n",
        opts.target.name(),
        mutator.name(),
        dbtr_trigger_count.map_or_else(|| "none".into(), |n| n.to_string()),
        duration
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|| "none".into()),
        opts.runner.timeout.as_millis(),
        opts.runner.qemu.display(),
        opts.runner.bios.display(),
        opts.runner.harness.display(),
        opts.runner.firmware_start,
        opts.runner.firmware_end,
    );
    fs::write(opts.output.join("run.txt"), manifest).map_err(|e| e.to_string())?;
    let mut rng = Rng::new(seed);
    let seeds = match opts.target {
        Target::Default => initial_cases(),
        Target::Dbtr => dbtr::initial_cases(),
    };
    let mut corpus = seeds.clone();
    let mut global_edges = HashSet::<Edge>::new();
    let mut global_blocks = HashSet::<u64>::new();
    let mut completed_edges = HashSet::<Edge>::new();
    let mut completed_blocks = HashSet::<u64>::new();
    let mut saved_findings = HashSet::<String>::new();
    let mut completed = 0usize;
    let mut findings = 0usize;
    let mut reproduced_candidates = 0usize;
    let mut executed = 0usize;
    let mut progress = BufWriter::new(
        fs::File::create(opts.output.join("progress.csv")).map_err(|e| e.to_string())?,
    );
    let mut call_log = if opts.target == Target::Dbtr {
        let mut writer = BufWriter::new(
            fs::File::create(opts.output.join("calls.csv")).map_err(|e| e.to_string())?,
        );
        writeln!(
            writer,
            "id,call_index,eid,fid,error,value,arena0,arena1,arena2,arena3"
        )
        .map_err(|e| e.to_string())?;
        Some(writer)
    } else {
        None
    };
    writeln!(
        progress,
        "id,mutator,fuzz_elapsed_ms,wall_elapsed_ms,elapsed_ms,outcome,calls,successful_calls,firmware_visits,case_edges,new_edges,total_edges,completed_edges,case_blocks,new_blocks,total_blocks,completed_blocks,corpus,candidate_findings,reproduced_candidates"
    )
    .map_err(|e| e.to_string())?;
    let campaign_start = Instant::now();
    let mut triage_duration = Duration::ZERO;
    println!(
        "seed={seed:#x}, target={}, mutator={}, max_execs={max_execs}, duration_secs={}, timeout_ms={}, output={}",
        opts.target.name(),
        mutator.name(),
        duration
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|| "none".into()),
        opts.runner.timeout.as_millis(),
        opts.output.display()
    );
    for id in 0..max_execs {
        if id > 0
            && duration
                .is_some_and(|d| campaign_start.elapsed().saturating_sub(triage_duration) >= d)
        {
            break;
        }
        let case = if id < seeds.len() {
            seeds[id].clone()
        } else {
            let parent = &corpus[rng.index(corpus.len())];
            match (opts.target, mutator) {
                (Target::Default, Mutator::Legacy) => mutate(parent, &mut rng),
                (Target::Default, Mutator::Uniform) => uniform_case(&mut rng),
                (Target::Default, Mutator::Structured) => structured_case(parent, &mut rng),
                (Target::Dbtr, Mutator::Legacy) => dbtr::mutate(parent, &mut rng),
                (Target::Dbtr, Mutator::Uniform) => dbtr::uniform_case(&mut rng),
                (Target::Dbtr, Mutator::Structured) => dbtr::structured_case(&mut rng),
            }
        };
        let nonce = seed.wrapping_add(id as u64 + 1);
        let run = opts.runner.run(&case, nonce)?;
        if let Some(log) = &mut call_log {
            for (call_index, (call, result)) in case.calls.iter().zip(&run.results).enumerate() {
                write!(
                    log,
                    "{id},{call_index},{:#x},{},{},{:#x}",
                    call.eid, call.fid, result.error, result.value
                )
                .map_err(|e| e.to_string())?;
                if let Some(words) = result.arena_words {
                    for word in words {
                        write!(log, ",{word:#x}").map_err(|e| e.to_string())?;
                    }
                } else {
                    write!(log, ",,,,").map_err(|e| e.to_string())?;
                }
                writeln!(log).map_err(|e| e.to_string())?;
            }
        }
        if id == 0 && run.edges.is_empty() {
            return Err(
                "QEMU produced no firmware coverage; check firmware range and trace settings"
                    .into(),
            );
        }
        if run.outcome == Outcome::Completed {
            completed += 1;
        }
        let old_count = global_edges.len();
        global_edges.extend(run.edges.iter().copied());
        let new_edges = global_edges.len() - old_count;
        let old_blocks = global_blocks.len();
        global_blocks.extend(run.blocks.iter().copied());
        let new_blocks = global_blocks.len() - old_blocks;
        let old_completed_edges = completed_edges.len();
        if run.outcome == Outcome::Completed {
            completed_edges.extend(run.edges.iter().copied());
            completed_blocks.extend(run.blocks.iter().copied());
        }
        let new_completed_edges = completed_edges.len() - old_completed_edges;
        if id < seeds.len() || new_completed_edges > 0 {
            let path = save_case(&opts.output.join("queue"), &format!("id_{id:06}"), &case)?;
            if id >= seeds.len() {
                corpus.push(case.clone());
            }
            println!(
                "#{id}: {:?}, +{new_completed_edges} completed edges, queue={}, {} ms, {}",
                run.outcome,
                corpus.len(),
                run.elapsed.as_millis(),
                path.display()
            );
        }
        if let Some(signature) = failure_signature(&case, &run, opts.target) {
            if !saved_findings.contains(&signature) {
                let triage_start = Instant::now();
                let replay = opts.runner.run(&case, nonce.wrapping_add(0x1000_0000))?;
                let reproduced =
                    failure_signature(&case, &replay, opts.target) == Some(signature.clone());
                let name = format!("id_{id:06}");
                let path = save_case(&opts.output.join("findings"), &name, &case)?;
                let report = format!(
                    "first: {signature}\nreplayed: {}\nreplay: {:?}\ncase: {}\n",
                    reproduced,
                    replay.outcome,
                    path.display()
                );
                fs::write(path.with_extension("txt"), report).map_err(|e| e.to_string())?;
                saved_findings.insert(signature.clone());
                findings += 1;
                if reproduced {
                    reproduced_candidates += 1;
                }
                println!(
                    "#{id}: candidate finding ({signature}); replayed={reproduced}; {}",
                    path.display()
                );
                triage_duration += triage_start.elapsed();
            }
        }
        executed = id + 1;
        let successful_calls = run.results.iter().filter(|r| r.error == 0).count();
        writeln!(
            progress,
            "{id},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            mutator.name(),
            campaign_start
                .elapsed()
                .saturating_sub(triage_duration)
                .as_millis(),
            campaign_start.elapsed().as_millis(),
            run.elapsed.as_millis(),
            outcome_name(&run.outcome),
            case.calls.len(),
            successful_calls,
            run.firmware_visits,
            run.edges.len(),
            new_edges,
            global_edges.len(),
            completed_edges.len(),
            run.blocks.len(),
            new_blocks,
            global_blocks.len(),
            completed_blocks.len(),
            corpus.len(),
            findings,
            reproduced_candidates,
        )
        .map_err(|e| e.to_string())?;
        if (id + 1) % 25 == 0 || id + 1 == max_execs {
            println!(
                "progress: {}/{} executions, {} completed, {} completed-case edges, {} completed-case blocks, {} corpus cases, {} candidate findings ({} reproduced)",
                id + 1,
                max_execs,
                completed,
                completed_edges.len(),
                completed_blocks.len(),
                corpus.len(),
                findings,
                reproduced_candidates,
            );
        }
    }
    progress.flush().map_err(|e| e.to_string())?;
    if let Some(log) = &mut call_log {
        log.flush().map_err(|e| e.to_string())?;
    }
    println!(
        "finished: {executed} executions, {} fuzz ms, {} wall ms, {completed} completed, {} completed-case edges, {} completed-case blocks, {} candidate findings ({} reproduced)",
        campaign_start
            .elapsed()
            .saturating_sub(triage_duration)
            .as_millis(),
        campaign_start.elapsed().as_millis(),
        completed_edges.len(),
        completed_blocks.len(),
        findings,
        reproduced_candidates,
    );
    Ok(())
}

fn replay(opts: Options, path: &Path, repeat: usize) -> Result<(), String> {
    opts.runner.validate()?;
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let case = InputCase::from_bytes(&data)?;
    for index in 0..repeat {
        let run = opts.runner.run(&case, index as u64 + 1)?;
        println!(
            "run {}: {:?}, {} ms, {} edges",
            index + 1,
            run.outcome,
            run.elapsed.as_millis(),
            run.edges.len()
        );
        for (call_index, (call, result)) in case.calls.iter().zip(&run.results).enumerate() {
            println!(
                "  call {call_index}: eid={:#x} fid={} error={} value={:#x}",
                call.eid, call.fid, result.error, result.value
            );
            if call.eid == DBTR {
                if let Some(words) = result.arena_words {
                    println!(
                        "    arena[0..32]: {:#x} {:#x} {:#x} {:#x}",
                        words[0], words[1], words[2], words[3]
                    );
                }
            }
        }
        if let Some(issue) = oracle_issue(&case, &run, opts.target) {
            println!("  oracle: {issue}");
        }
        if run.outcome != Outcome::Completed {
            for frame in run
                .serial
                .lines()
                .filter(|line| line.starts_with("HISAME:"))
                .take(16)
            {
                println!("  {frame}");
            }
            println!(
                "  serial log: {}",
                opts.runner.work_dir.join("serial.log").display()
            );
            if !run.stderr.trim().is_empty() {
                println!(
                    "  qemu stderr: {}",
                    run.stderr.trim().chars().take(1024).collect::<String>()
                );
            }
        }
    }
    Ok(())
}

fn main() {
    let result = match parse_options() {
        Ok(None) => {
            print!("{USAGE}");
            return;
        }
        Ok(Some(opts)) => match opts.mode {
            Mode::Fuzz {
                max_execs,
                seed,
                mutator,
                duration,
            } => fuzz(opts, max_execs, seed, mutator, duration),
            Mode::Replay { ref case, repeat } => {
                let path = case.clone();
                replay(opts, &path, repeat)
            }
        },
        Err(e) => Err(e),
    };
    if let Err(error) = result {
        eprintln!("error: {error}\n\n{USAGE}");
        std::process::exit(1);
    }
}
