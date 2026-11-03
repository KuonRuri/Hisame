use crate::case::InputCase;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

// The harness linker script places _start at this address.
const HARNESS_ENTRY: u64 = 0x8020_0000;
// The harness text is currently under 4 KiB. Trace the surrounding region so
// returns to S-mode separate firmware visits made by distinct SBI calls.
const HARNESS_TRACE_END: u64 = 0x8030_0000;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Edge(pub u64, pub u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallResult {
    pub error: i64,
    pub value: u64,
    pub arena_words: Option<[u64; 4]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    GuestTrap { cause: u64, tval: u64, pc: u64 },
    TimedOut,
    OutputLimit,
    AbnormalExit,
}

#[derive(Debug)]
pub struct RunResult {
    pub outcome: Outcome,
    pub results: Vec<CallResult>,
    pub edges: HashSet<Edge>,
    pub blocks: HashSet<u64>,
    pub firmware_visits: usize,
    pub serial: String,
    pub stderr: String,
    pub elapsed: Duration,
}

pub struct Runner {
    pub qemu: PathBuf,
    pub bios: PathBuf,
    pub harness: PathBuf,
    pub work_dir: PathBuf,
    pub timeout: Duration,
    pub firmware_start: u64,
    pub firmware_end: u64,
}

impl Runner {
    pub fn validate(&self) -> Result<(), String> {
        if !executable_exists(&self.qemu) {
            return Err(format!("QEMU binary missing: {}", self.qemu.display()));
        }
        if !self.bios.exists() {
            return Err(format!("OpenSBI binary missing: {}", self.bios.display()));
        }
        if !self.harness.exists() {
            return Err(format!(
                "harness missing: {} (run scripts/build.sh)",
                self.harness.display()
            ));
        }
        if self.firmware_start >= self.firmware_end {
            return Err("firmware coverage range is empty".into());
        }
        fs::create_dir_all(&self.work_dir).map_err(|e| e.to_string())
    }

    pub fn run(&self, case: &InputCase, nonce: u64) -> Result<RunResult, String> {
        let input_path = self.work_dir.join("input.bin");
        let serial_path = self.work_dir.join("serial.log");
        let trace_path = self.work_dir.join("trace.log");
        let stderr_path = self.work_dir.join("qemu.stderr");
        fs::write(&input_path, case.to_bytes(nonce)).map_err(|e| e.to_string())?;
        for path in [&serial_path, &trace_path, &stderr_path] {
            let _ = fs::remove_file(path);
        }
        let stderr_file = File::create(&stderr_path).map_err(|e| e.to_string())?;
        let loader = format!(
            "loader,file={},addr=0x88000000,force-raw=on",
            input_path.display()
        );
        let filter = format!(
            "{:#x}..{:#x},{HARNESS_ENTRY:#x}..{:#x}",
            self.firmware_start,
            self.firmware_end - 1,
            HARNESS_TRACE_END - 1,
        );
        let start = Instant::now();
        let mut child = Command::new(&self.qemu)
            .args(["-machine", "virt", "-m", "256M", "-smp", "1"])
            .args(["-display", "none", "-monitor", "none"])
            .arg("-serial")
            .arg(format!("file:{}", serial_path.display()))
            .arg("-bios")
            .arg(&self.bios)
            .arg("-kernel")
            .arg(&self.harness)
            .arg("-device")
            .arg(loader)
            .args(["-d", "exec", "-dfilter"])
            .arg(filter)
            .arg("-D")
            .arg(&trace_path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|e| format!("cannot start QEMU: {e}"))?;

        let (timed_out, output_limit, status) = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break (false, false, status);
            }
            let oversized = [
                (&trace_path, 64u64 * 1024 * 1024),
                (&serial_path, 2u64 * 1024 * 1024),
            ]
            .iter()
            .any(|(path, max)| fs::metadata(path).map(|m| m.len() > *max).unwrap_or(false));
            if start.elapsed() >= self.timeout || oversized {
                let _ = child.kill();
                let status = child.wait().map_err(|e| e.to_string())?;
                break (!oversized, oversized, status);
            }
            thread::sleep(Duration::from_millis(5));
        };

        let serial = read_log(&serial_path, 2 * 1024 * 1024);
        let stderr = read_log(&stderr_path, 64 * 1024);
        let (began, done, trap, results) = parse_serial(&serial, nonce);
        if !began && trap.is_none() {
            return Err(format!(
                "QEMU did not reach harness: {}",
                stderr.trim().chars().take(500).collect::<String>()
            ));
        }
        let outcome = if output_limit {
            Outcome::OutputLimit
        } else if timed_out {
            Outcome::TimedOut
        } else if let Some((cause, tval, pc)) = trap {
            Outcome::GuestTrap { cause, tval, pc }
        } else if status.success()
            && done == Some(case.calls.len())
            && results.len() == case.calls.len()
        {
            Outcome::Completed
        } else {
            Outcome::AbnormalExit
        };
        let coverage = collect_coverage(&trace_path, self.firmware_start, self.firmware_end)
            .map_err(|e| format!("cannot read QEMU trace: {e}"))?;
        Ok(RunResult {
            outcome,
            results,
            edges: coverage.edges,
            blocks: coverage.blocks,
            firmware_visits: coverage.firmware_visits,
            serial,
            stderr,
            elapsed: start.elapsed(),
        })
    }
}

fn executable_exists(path: &Path) -> bool {
    if path.components().count() > 1 || path.is_absolute() {
        return path.is_file();
    }
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|dir| dir.join(path).is_file()))
        .unwrap_or(false)
}

fn read_log(path: &PathBuf, max: usize) -> String {
    let Ok(file) = File::open(path) else {
        return String::new();
    };
    let mut data = Vec::new();
    if file.take(max as u64).read_to_end(&mut data).is_ok() {
        String::from_utf8_lossy(&data).into_owned()
    } else {
        String::new()
    }
}

fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value, 16).ok()
}

fn parse_serial(
    serial: &str,
    nonce: u64,
) -> (
    bool,
    Option<usize>,
    Option<(u64, u64, u64)>,
    Vec<CallResult>,
) {
    let token = format!("{nonce:016x}");
    let mut began = false;
    let mut done = None;
    let mut trap = None;
    let mut results = Vec::new();
    for line in serial.lines() {
        let fields: Vec<_> = line.trim().split(':').collect();
        match fields.as_slice() {
            ["HISAME", "BEGIN", n] if *n == token => began = true,
            ["HISAME", "RESULT", n, index, error, value] if *n == token => {
                if parse_hex(index) == Some(results.len() as u64) {
                    if let (Some(error), Some(value)) = (parse_hex(error), parse_hex(value)) {
                        results.push(CallResult {
                            error: error as i64,
                            value,
                            arena_words: None,
                        });
                    }
                }
            }
            ["HISAME", "ARENA", n, index, w0, w1, w2, w3] if *n == token => {
                if parse_hex(index) == Some(results.len().saturating_sub(1) as u64) {
                    let words = [w0, w1, w2, w3];
                    if let Some(values) = words
                        .iter()
                        .map(|word| parse_hex(word))
                        .collect::<Option<Vec<_>>>()
                    {
                        if let Some(last) = results.last_mut() {
                            last.arena_words = Some(values.try_into().unwrap());
                        }
                    }
                }
            }
            ["HISAME", "DONE", n, count] if *n == token => {
                done = parse_hex(count).map(|v| v as usize)
            }
            ["HISAME", "TRAP", n, cause, tval, pc] if *n == token => {
                if let (Some(cause), Some(tval), Some(pc)) =
                    (parse_hex(cause), parse_hex(tval), parse_hex(pc))
                {
                    trap = Some((cause, tval, pc));
                }
            }
            _ => {}
        }
    }
    (began, done, trap, results)
}

#[derive(Debug)]
struct Coverage {
    edges: HashSet<Edge>,
    blocks: HashSet<u64>,
    firmware_visits: usize,
}

fn collect_coverage(path: &Path, start: u64, end: u64) -> std::io::Result<Coverage> {
    let file = File::open(path)?;
    collect_coverage_from_reader(BufReader::new(file), start, end)
}

fn collect_coverage_from_reader(
    reader: impl BufRead,
    start: u64,
    end: u64,
) -> std::io::Result<Coverage> {
    let mut edges = HashSet::new();
    let mut blocks = HashSet::new();
    let mut previous = None;
    let mut reached_harness = false;
    let mut firmware_visits = 0;
    for line in reader.lines() {
        let line = line?;
        let Some(pc) = parse_trace_pc(&line) else {
            continue;
        };
        if pc == HARNESS_ENTRY {
            reached_harness = true;
            previous = None;
            continue;
        }
        if !reached_harness {
            continue;
        }
        if pc >= start && pc < end {
            if previous.is_none() {
                firmware_visits += 1;
            }
            edges.insert(Edge(previous.unwrap_or(0), pc));
            blocks.insert(pc);
            previous = Some(pc);
        } else {
            // QEMU also logs the harness. A transition through S-mode ends
            // the prior SBI call, so it cannot be a firmware CFG edge.
            previous = None;
        }
    }
    if reached_harness {
        Ok(Coverage {
            edges,
            blocks,
            firmware_visits,
        })
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "QEMU trace never reached the harness entry",
        ))
    }
}

fn parse_trace_pc(line: &str) -> Option<u64> {
    if !line.starts_with("Trace ") {
        return None;
    }
    // QEMU prints the host TB address before the bracket. The second field
    // inside the bracket is the guest PC, which is the coverage signal.
    let (_, bracket) = line.split_once('[')?;
    let pc = bracket.split('/').nth(1)?;
    u64::from_str_radix(pc, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_result_frame() {
        let input = "\nHISAME:BEGIN:000000000000002a\nHISAME:RESULT:000000000000002a:0000000000000000:fffffffffffffffe:0000000000000000\nHISAME:DONE:000000000000002a:0000000000000001\n";
        let (began, done, trap, results) = parse_serial(input, 42);
        assert!(began);
        assert_eq!(done, Some(1));
        assert!(trap.is_none());
        assert_eq!(results[0].error, -2);
    }

    #[test]
    fn parses_dbtr_arena_snapshot() {
        let input = "\nHISAME:BEGIN:000000000000002a\n\
                     HISAME:RESULT:000000000000002a:0000000000000000:0000000000000000:0000000000000000\n\
                     HISAME:ARENA:000000000000002a:0000000000000000:0000000000000001:6000000000000012:0000000088000ff0:0000000000000000\n\
                     HISAME:DONE:000000000000002a:0000000000000001\n";
        let (_, done, _, results) = parse_serial(input, 42);
        assert_eq!(done, Some(1));
        assert_eq!(
            results[0].arena_words,
            Some([1, 0x6000_0000_0000_0012, 0x8800_0ff0, 0])
        );
    }

    #[test]
    fn parses_qemu_trace_pc() {
        assert_eq!(
            parse_trace_pc("Trace 0: 0x78ed7c000440 [001411ad/0000000080001234/02c24003/ff020000]"),
            Some(0x80001234)
        );
        assert_eq!(parse_trace_pc("IN: foo"), None);
    }

    #[test]
    fn coverage_starts_at_harness_entry() {
        let trace = "Trace 0: 0x1 [0/0000000080000100/0/0]\n\
                     Trace 0: 0x2 [0/0000000080000108/0/0]\n\
                     Trace 0: 0x3 [0/0000000080200000/0/0]\n\
                     Trace 0: 0x4 [0/0000000080001000/0/0]\n\
                     Trace 0: 0x5 [0/0000000080200010/0/0]\n\
                     Trace 0: 0x6 [0/0000000080001004/0/0]\n";
        let coverage = collect_coverage_from_reader(trace.as_bytes(), 0x8000_0000, 0x8020_0000)
            .expect("valid trace");
        assert_eq!(
            coverage.edges,
            HashSet::from([Edge(0, 0x8000_1000), Edge(0, 0x8000_1004)])
        );
        assert_eq!(coverage.firmware_visits, 2);
    }

    #[test]
    fn coverage_requires_harness_entry() {
        let trace = "Trace 0: 0x1 [0/0000000080000100/0/0]\n";
        let error = collect_coverage_from_reader(trace.as_bytes(), 0x8000_0000, 0x8020_0000)
            .expect_err("missing harness entry");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn separate_sbi_calls_do_not_create_cross_call_edges() {
        let trace = "Trace 0: 0x1 [0/0000000080200000/0/0]\n\
                     Trace 0: 0x2 [0/00000000802001a0/0/0]\n\
                     Trace 0: 0x3 [0/00000000800004f8/0/0]\n\
                     Trace 0: 0x4 [0/000000008000062c/0/0]\n\
                     Trace 0: 0x5 [0/00000000802001a4/0/0]\n\
                     Trace 0: 0x6 [0/00000000802001a0/0/0]\n\
                     Trace 0: 0x7 [0/00000000800004f8/0/0]\n";
        let coverage = collect_coverage_from_reader(trace.as_bytes(), 0x8000_0000, 0x8020_0000)
            .expect("valid trace");
        assert_eq!(coverage.firmware_visits, 2);
        assert_eq!(coverage.blocks.len(), 2);
        assert_eq!(
            coverage.edges,
            HashSet::from([Edge(0, 0x8000_04f8), Edge(0x8000_04f8, 0x8000_062c)])
        );
    }
}
