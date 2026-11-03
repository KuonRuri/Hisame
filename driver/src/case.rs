use std::convert::TryInto;

pub const MAX_CALLS: usize = 8;
pub const CALL_SIZE: usize = 72;
pub const CALLS_OFFSET: usize = 16;
pub const ARENA_OFFSET: usize = 1024;
pub const ARENA_SIZE: usize = 4096;
pub const CASE_SIZE: usize = ARENA_OFFSET + ARENA_SIZE;
pub const BASE: u64 = 0x10;
pub const DBCN: u64 = 0x4442_434e;
pub const DBTR: u64 = 0x4442_5452;
pub const PMU: u64 = 0x504d_55;
pub const TIME: u64 = 0x5449_4d45;
pub const HSM: u64 = 0x4853_4d;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutator {
    Legacy,
    Uniform,
    Structured,
}

impl Mutator {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "legacy" => Ok(Self::Legacy),
            "uniform" => Ok(Self::Uniform),
            "structured" => Ok(Self::Structured),
            _ => Err(format!("unknown mutator: {value}")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Uniform => "uniform",
            Self::Structured => "structured",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub eid: u64,
    pub fid: u64,
    pub args: [u64; 6],
    pub ptr_mask: u8,
}

impl Call {
    pub fn new(eid: u64, fid: u64, args: [u64; 6], ptr_mask: u8) -> Self {
        Self {
            eid,
            fid,
            args,
            ptr_mask,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputCase {
    pub calls: Vec<Call>,
    pub arena: [u8; ARENA_SIZE],
}

impl InputCase {
    pub fn single(call: Call) -> Self {
        Self {
            calls: vec![call],
            arena: [0; ARENA_SIZE],
        }
    }

    pub fn to_bytes(&self, nonce: u64) -> Vec<u8> {
        assert!((1..=MAX_CALLS).contains(&self.calls.len()));
        let mut bytes = vec![0u8; CASE_SIZE];
        bytes[..4].copy_from_slice(b"HSM1");
        bytes[4] = self.calls.len() as u8;
        bytes[5] = 1;
        bytes[8..16].copy_from_slice(&nonce.to_le_bytes());
        for (i, call) in self.calls.iter().enumerate() {
            let base = CALLS_OFFSET + i * CALL_SIZE;
            bytes[base..base + 8].copy_from_slice(&call.eid.to_le_bytes());
            bytes[base + 8..base + 16].copy_from_slice(&call.fid.to_le_bytes());
            for (n, value) in call.args.iter().enumerate() {
                let offset = base + 16 + n * 8;
                bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            bytes[base + 64] = call.ptr_mask;
        }
        bytes[ARENA_OFFSET..].copy_from_slice(&self.arena);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != CASE_SIZE || &bytes[..4] != b"HSM1" || bytes[5] != 1 {
            return Err("invalid case header or size".into());
        }
        let count = bytes[4] as usize;
        if !(1..=MAX_CALLS).contains(&count) {
            return Err("invalid call count".into());
        }
        let mut calls = Vec::with_capacity(count);
        for i in 0..count {
            let base = CALLS_OFFSET + i * CALL_SIZE;
            let eid = u64::from_le_bytes(bytes[base..base + 8].try_into().unwrap());
            let fid = u64::from_le_bytes(bytes[base + 8..base + 16].try_into().unwrap());
            let mut args = [0u64; 6];
            for (n, arg) in args.iter_mut().enumerate() {
                let offset = base + 16 + n * 8;
                *arg = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            }
            let ptr_mask = bytes[base + 64];
            if ptr_mask & !0x3f != 0 {
                return Err("invalid pointer mask".into());
            }
            calls.push(Call {
                eid,
                fid,
                args,
                ptr_mask,
            });
        }
        let mut arena = [0u8; ARENA_SIZE];
        arena.copy_from_slice(&bytes[ARENA_OFFSET..]);
        Ok(Self { calls, arena })
    }
}

pub fn initial_cases() -> Vec<InputCase> {
    let version = InputCase::single(Call::new(BASE, 0, [0; 6], 0));
    let impl_id = InputCase::single(Call::new(BASE, 1, [0; 6], 0));
    let impl_version = InputCase::single(Call::new(BASE, 2, [0; 6], 0));
    let probe = InputCase::single(Call::new(BASE, 3, [DBCN, 0, 0, 0, 0, 0], 0));
    let probe_pmu = InputCase::single(Call::new(BASE, 3, [PMU, 0, 0, 0, 0, 0], 0));
    let vendor_id = InputCase::single(Call::new(BASE, 4, [0; 6], 0));
    let arch_id = InputCase::single(Call::new(BASE, 5, [0; 6], 0));
    let machine_impl_id = InputCase::single(Call::new(BASE, 6, [0; 6], 0));
    let mut write = InputCase::single(Call::new(DBCN, 0, [4, 0, 0, 0, 0, 0], 1 << 1));
    write.arena[..4].copy_from_slice(b"FUZZ");
    let read = InputCase::single(Call::new(DBCN, 1, [0, 0, 0, 0, 0, 0], 1 << 1));
    let pmu = InputCase::single(Call::new(PMU, 0, [0; 6], 0));
    let pmu_info = InputCase::single(Call::new(PMU, 1, [0; 6], 0));
    let mut sequence = write.clone();
    sequence
        .calls
        .insert(0, Call::new(BASE, 3, [DBCN, 0, 0, 0, 0, 0], 0));
    let mut pmu_sequence = pmu.clone();
    pmu_sequence.calls.push(pmu_info.calls[0].clone());
    vec![
        version,
        impl_id,
        probe,
        write,
        read,
        pmu,
        sequence,
        impl_version,
        probe_pmu,
        vendor_id,
        arch_id,
        machine_impl_id,
        pmu_info,
        pmu_sequence,
    ]
}

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn index(&mut self, len: usize) -> usize {
        (self.next() as usize) % len
    }
}

pub fn mutate(parent: &InputCase, rng: &mut Rng) -> InputCase {
    let mut case = parent.clone();
    match rng.index(7) {
        0 | 1 => {
            let c = rng.index(case.calls.len());
            mutate_arg(&mut case.calls[c], rng);
        }
        2 => {
            if !mutate_used_buffer(&mut case, rng) {
                let c = rng.index(case.calls.len());
                mutate_arg(&mut case.calls[c], rng);
            }
        }
        3 => {
            let c = rng.index(case.calls.len());
            let a = rng.index(6);
            case.calls[c].ptr_mask ^= 1 << a;
            case.calls[c].args[a] = [0, 1, 4095, 4096, u64::MAX][rng.index(5)];
        }
        4 => {
            let c = rng.index(case.calls.len());
            let choices = [
                Call::new(BASE, 3, [DBCN, 0, 0, 0, 0, 0], 0),
                Call::new(BASE, 3, [PMU, 0, 0, 0, 0, 0], 0),
                Call::new(BASE, 2, [0; 6], 0),
                Call::new(BASE, 4, [0; 6], 0),
                Call::new(BASE, 5, [0; 6], 0),
                Call::new(BASE, 6, [0; 6], 0),
                Call::new(DBCN, 0, [4, 0, 0, 0, 0, 0], 1 << 1),
                Call::new(DBCN, 1, [4, 0, 0, 0, 0, 0], 1 << 1),
                Call::new(DBCN, 2, [b'X' as u64, 0, 0, 0, 0, 0], 0),
                Call::new(PMU, 0, [0; 6], 0),
                Call::new(PMU, 1, [0; 6], 0),
            ];
            case.calls[c] = choices[rng.index(choices.len())].clone();
        }
        5 => {
            if case.calls.len() < MAX_CALLS && rng.index(2) == 0 {
                let c = rng.index(case.calls.len());
                case.calls.insert(c, case.calls[c].clone());
            } else if case.calls.len() > 1 {
                let c = rng.index(case.calls.len());
                case.calls.remove(c);
            }
        }
        _ => {
            let c = rng.index(case.calls.len());
            if rng.index(2) == 0 {
                case.calls[c].fid = rng.next() & 15;
            } else {
                case.calls[c].eid = rng.next() & 0xffff_ffff;
            }
        }
    }
    case
}

/// An unguided baseline with the same EID/FID vocabulary as the structured
/// generator, but no call-specific argument or sequence construction.
pub fn uniform_case(rng: &mut Rng) -> InputCase {
    const OPS: &[(u64, u64)] = &[
        (BASE, 0),
        (BASE, 1),
        (BASE, 2),
        (BASE, 3),
        (BASE, 4),
        (BASE, 5),
        (BASE, 6),
        (DBCN, 0),
        (DBCN, 1),
        (DBCN, 2),
        (PMU, 0),
        (PMU, 1),
        (PMU, 2),
        (PMU, 3),
        (PMU, 4),
        (PMU, 5),
    ];
    const VALUES: [u64; 12] = [0, 1, 2, 3, 4, 16, 19, 34, 35, 4095, 4096, u64::MAX];
    let mut calls = Vec::with_capacity(4);
    for _ in 0..(1 + rng.index(4)) {
        let (eid, fid) = OPS[rng.index(OPS.len())];
        let mut args = [0; 6];
        for arg in &mut args {
            *arg = VALUES[rng.index(VALUES.len())];
        }
        // Keep console output bounded so the baseline is comparable by time.
        if eid == DBCN && fid <= 1 {
            args[0] = [0, 1, 4, 16, 4095, 4096, 4097][rng.index(7)];
        }
        let ptr_mask = if eid == DBCN && fid <= 1 && rng.index(2) == 0 {
            1 << 1
        } else {
            0
        };
        calls.push(Call::new(eid, fid, args, ptr_mask));
    }
    InputCase {
        calls,
        arena: [b'X'; ARENA_SIZE],
    }
}

/// Constructs calls around the SBI argument relationships being studied. It
/// selects the extension from the coverage corpus parent, then varies a
/// boundary or a stateful PMU sequence within that extension.
pub fn structured_case(parent: &InputCase, rng: &mut Rng) -> InputCase {
    let family = if rng.index(4) == 0 {
        rng.index(3)
    } else {
        match parent.calls[0].eid {
            DBCN => 1,
            PMU => 2,
            _ => 0,
        }
    };
    match family {
        0 => {
            let fid = rng.index(7) as u64;
            let mut args = [0; 6];
            if fid == 3 {
                args[0] = [BASE, DBCN, PMU, TIME, HSM, 0, u64::MAX][rng.index(7)];
            }
            InputCase::single(Call::new(BASE, fid, args, 0))
        }
        1 => {
            let fid = rng.index(3) as u64;
            let mut args = [0; 6];
            let mut ptr_mask = 0;
            if fid <= 1 {
                args[0] = [0, 1, 2, 4, 16, 4095, 4096, 4097][rng.index(8)];
                args[1] = [0, 1, 4095, 4096, u64::MAX][rng.index(5)];
                if rng.index(5) != 0 {
                    ptr_mask = 1 << 1;
                } else {
                    args[1] = [0, 0x8000_0000, u64::MAX][rng.index(3)];
                }
            } else {
                args[0] = [0, b'X' as u64, 255][rng.index(3)];
            }
            InputCase {
                calls: vec![Call::new(DBCN, fid, args, ptr_mask)],
                arena: [b'X'; ARENA_SIZE],
            }
        }
        _ => {
            if rng.index(4) == 0 {
                let index = [0, 3, 19, 34, 35, u64::MAX][rng.index(6)];
                return InputCase {
                    calls: vec![
                        Call::new(PMU, 0, [0; 6], 0),
                        Call::new(PMU, 1, [index, 0, 0, 0, 0, 0], 0),
                    ],
                    arena: [0; ARENA_SIZE],
                };
            }
            // On the QEMU virt reference platform, 19 is the first firmware
            // counter. Its event mapping enables a meaningful lifecycle.
            let index = [19, 19, 19, 20, 34, 35][rng.index(6)];
            let event = [0xf_0000, 0xf_0001, 0xf_0005][rng.index(3)];
            let mut calls = vec![
                Call::new(PMU, 2, [index, 1, 0, event, 0, 0], 0),
                Call::new(PMU, 3, [index, 1, 0, 0, 0, 0], 0),
                Call::new(PMU, 5, [index, 0, 0, 0, 0, 0], 0),
                Call::new(PMU, 4, [index, 1, 1, 0, 0, 0], 0),
            ];
            if rng.index(4) == 0 {
                // One repeated transition exercises already-started/stopped
                // handling without losing the rest of the lifecycle.
                let at = if rng.index(2) == 0 { 2 } else { 4 };
                calls.insert(at, calls[at - 1].clone());
            }
            InputCase {
                calls,
                arena: [0; ARENA_SIZE],
            }
        }
    }
}

fn mutate_arg(call: &mut Call, rng: &mut Rng) {
    let arg_index = match (call.eid, call.fid) {
        (BASE, 3) => 0,
        (DBCN, 0 | 1) => [0, 0, 1, 2][rng.index(4)],
        (DBCN, 2) => 0,
        (PMU, 1) => 0,
        _ => rng.index(6),
    };
    let old = call.args[arg_index];
    let bounds = [0, 1, 2, 4, 255, 4095, 4096, u32::MAX as u64, u64::MAX];
    call.args[arg_index] = if call.eid == BASE && call.fid == 3 && rng.index(2) == 0 {
        [BASE, DBCN, PMU, 0, u64::MAX][rng.index(5)]
    } else {
        match rng.index(4) {
            0 => bounds[rng.index(bounds.len())],
            1 => old.wrapping_add(1),
            2 => old.wrapping_sub(1),
            _ => old ^ (1u64 << rng.index(64)),
        }
    };
}

fn mutate_used_buffer(case: &mut InputCase, rng: &mut Rng) -> bool {
    let spans: Vec<_> = case
        .calls
        .iter()
        .filter(|call| call.eid == DBCN && call.fid == 0 && call.ptr_mask & (1 << 1) != 0)
        .filter_map(|call| {
            let offset = usize::try_from(call.args[1]).ok()?;
            let length = usize::try_from(call.args[0]).ok()?;
            if offset >= ARENA_SIZE || length == 0 {
                return None;
            }
            Some((offset, length.min(ARENA_SIZE - offset)))
        })
        .collect();
    if spans.is_empty() {
        return false;
    }
    let (offset, length) = spans[rng.index(spans.len())];
    let index = offset + rng.index(length);
    case.arena[index] = rng.next() as u8;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_pointer_mask() {
        let case = initial_cases().remove(3);
        let data = case.to_bytes(42);
        assert_eq!(InputCase::from_bytes(&data).unwrap(), case);
        assert_eq!(data[CALLS_OFFSET + 64], 2);
        assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), 42);
    }

    #[test]
    fn mutations_remain_well_formed() {
        let mut rng = Rng::new(17);
        let mut case = initial_cases().remove(3);
        for _ in 0..500 {
            case = mutate(&case, &mut rng);
            assert!((1..=MAX_CALLS).contains(&case.calls.len()));
            assert_eq!(InputCase::from_bytes(&case.to_bytes(1)).unwrap(), case);
        }
    }

    #[test]
    fn experiment_generators_remain_well_formed() {
        let mut rng = Rng::new(17);
        let mut parent = initial_cases().remove(5);
        for _ in 0..500 {
            let random = uniform_case(&mut rng);
            let structured = structured_case(&parent, &mut rng);
            for case in [&random, &structured] {
                assert!((1..=MAX_CALLS).contains(&case.calls.len()));
                assert_eq!(InputCase::from_bytes(&case.to_bytes(1)).unwrap(), *case);
            }
            parent = structured;
        }
    }
}
