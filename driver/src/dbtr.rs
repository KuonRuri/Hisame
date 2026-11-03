use crate::case::{ARENA_SIZE, BASE, Call, DBTR, InputCase, MAX_CALLS, Rng};

// RV64 tdata1 type is in bits 63:60. These configurations watch an arena
// address that the harness does not access after the input is loaded.
const MCONTROL: u64 = 2 << 60;
const MCONTROL6: u64 = 6 << 60;
const S_MODE_STORE: u64 = (1 << 4) | (1 << 1);
const QUIET_ADDRESS: u64 = 0x8800_0ff0;
const BOUNDS: [u64; 9] = [0, 1, 2, 3, 8, 4095, 4096, u32::MAX as u64, u64::MAX];

fn call(fid: u64, args: [u64; 6]) -> Call {
    Call::new(DBTR, fid, args, 0)
}

fn shmem() -> Call {
    Call::new(DBTR, 1, [0; 6], 1)
}

fn clear_shmem() -> Call {
    call(1, [u64::MAX, u64::MAX, 0, 0, 0, 0])
}

fn trigger_case(tdata1: u64, calls: Vec<Call>) -> InputCase {
    let mut arena = [0; ARENA_SIZE];
    arena[8..16].copy_from_slice(&tdata1.to_le_bytes());
    arena[16..24].copy_from_slice(&QUIET_ADDRESS.to_le_bytes());
    InputCase { calls, arena }
}

fn lifecycle(tdata1: u64) -> InputCase {
    trigger_case(
        tdata1,
        vec![
            call(0, [0; 6]),
            shmem(),
            call(3, [1, 0, 0, 0, 0, 0]),
            call(2, [0, 1, 0, 0, 0, 0]),
            call(7, [0, 1, 0, 0, 0, 0]),
            call(6, [0, 1, 0, 0, 0, 0]),
            call(5, [0, 1, 0, 0, 0, 0]),
            clear_shmem(),
        ],
    )
}

pub fn initial_cases() -> Vec<InputCase> {
    vec![
        InputCase::single(Call::new(BASE, 3, [DBTR, 0, 0, 0, 0, 0], 0)),
        InputCase::single(call(0, [0; 6])),
        InputCase::single(call(0, [MCONTROL, 0, 0, 0, 0, 0])),
        InputCase::single(call(0, [MCONTROL6, 0, 0, 0, 0, 0])),
        InputCase::single(call(2, [0, 1, 0, 0, 0, 0])),
        trigger_case(
            MCONTROL6 | S_MODE_STORE,
            vec![
                call(0, [0; 6]),
                shmem(),
                call(2, [0, 1, 0, 0, 0, 0]),
                clear_shmem(),
            ],
        ),
        lifecycle(MCONTROL | S_MODE_STORE),
        lifecycle(MCONTROL6 | S_MODE_STORE),
        trigger_case(
            MCONTROL6 | S_MODE_STORE,
            vec![
                call(0, [0; 6]),
                shmem(),
                call(3, [1, 0, 0, 0, 0, 0]),
                call(4, [1, 0, 0, 0, 0, 0]),
                call(5, [0, 1, 0, 0, 0, 0]),
                clear_shmem(),
            ],
        ),
        trigger_case(
            MCONTROL6 | S_MODE_STORE,
            vec![
                call(0, [0; 6]),
                Call::new(DBTR, 1, [1, 0, 0, 0, 0, 0], 1),
                call(2, [0, 1, 0, 0, 0, 0]),
            ],
        ),
    ]
}

/// Independent raw DBTR calls for comparison with the structured generator.
pub fn uniform_case(rng: &mut Rng) -> InputCase {
    let mut calls = Vec::with_capacity(4);
    for _ in 0..(1 + rng.index(4)) {
        let fid = rng.index(8) as u64;
        let mut args = [0; 6];
        for arg in &mut args {
            *arg = BOUNDS[rng.index(BOUNDS.len())];
        }
        if fid == 0 && rng.index(2) == 0 {
            args[0] = [0, MCONTROL, MCONTROL6][rng.index(3)];
        }
        let mask = if fid == 1 && rng.index(2) == 0 { 1 } else { 0 };
        calls.push(Call::new(DBTR, fid, args, mask));
    }
    let mut arena = [0; ARENA_SIZE];
    for word in arena[..64].chunks_exact_mut(8) {
        word.copy_from_slice(&rng.next().to_le_bytes());
    }
    InputCase { calls, arena }
}

/// Exercises both valid trigger lifecycles and boundary/error paths.
pub fn structured_case(rng: &mut Rng) -> InputCase {
    let kind = rng.index(6);
    let tdata1 = match rng.index(6) {
        0 => MCONTROL | S_MODE_STORE,
        1 | 2 | 3 => MCONTROL6 | S_MODE_STORE,
        4 => MCONTROL6,
        _ => u64::MAX,
    };
    match kind {
        0 => InputCase::single(call(
            0,
            [
                [0, MCONTROL, MCONTROL6, u64::MAX][rng.index(4)],
                0,
                0,
                0,
                0,
                0,
            ],
        )),
        1 => {
            let mut case = lifecycle(tdata1);
            // Exercise a single invalid index or mask while keeping the setup.
            if rng.index(3) == 0 {
                let at = [3, 4, 5, 6][rng.index(4)];
                case.calls[at].args[0] = [0, 1, 2, u64::MAX][rng.index(4)];
            }
            case
        }
        2 => trigger_case(
            tdata1,
            vec![
                call(0, [0; 6]),
                shmem(),
                call(3, [1, 0, 0, 0, 0, 0]),
                call(4, [1, 0, 0, 0, 0, 0]),
                call(2, [0, 1, 0, 0, 0, 0]),
                call(5, [0, 1, 0, 0, 0, 0]),
                clear_shmem(),
            ],
        ),
        3 => trigger_case(
            tdata1,
            vec![
                call(0, [0; 6]),
                shmem(),
                call(
                    2,
                    [
                        [0, 1, 2, u64::MAX][rng.index(4)],
                        [0, 1, 2, 3, u64::MAX][rng.index(5)],
                        0,
                        0,
                        0,
                        0,
                    ],
                ),
                call(3, [[0, 1, 2, 3, u64::MAX][rng.index(5)], 0, 0, 0, 0, 0]),
                clear_shmem(),
            ],
        ),
        4 => {
            let mut setup = Call::new(DBTR, 1, [0; 6], 1);
            match rng.index(4) {
                0 => setup.args[0] = 1,
                1 => setup.args[2] = 1,
                2 => {
                    setup.ptr_mask = 0;
                    setup.args[0] = 0;
                }
                _ => {
                    setup.ptr_mask = 0;
                    setup.args[0] = u64::MAX;
                    setup.args[1] = 0;
                }
            }
            trigger_case(
                tdata1,
                vec![call(0, [0; 6]), setup, call(2, [0, 1, 0, 0, 0, 0])],
            )
        }
        _ => trigger_case(
            tdata1,
            vec![
                call(0, [0; 6]),
                call(3, [1, 0, 0, 0, 0, 0]),
                call(4, [1, 0, 0, 0, 0, 0]),
                call(5, [0, 1, 0, 0, 0, 0]),
            ],
        ),
    }
}

pub fn mutate(parent: &InputCase, rng: &mut Rng) -> InputCase {
    if !parent.calls.iter().any(|c| c.eid == DBTR) {
        return structured_case(rng);
    }
    let mut case = parent.clone();
    match rng.index(7) {
        0 | 1 => {
            let c = rng.index(case.calls.len());
            let a = rng.index(6);
            let old = case.calls[c].args[a];
            case.calls[c].args[a] = match rng.index(4) {
                0 => BOUNDS[rng.index(BOUNDS.len())],
                1 => old.wrapping_add(1),
                2 => old.wrapping_sub(1),
                _ => old ^ (1 << rng.index(64)),
            };
        }
        2 => {
            let word = rng.index(8);
            let offset = word * 8;
            let old = u64::from_le_bytes(case.arena[offset..offset + 8].try_into().unwrap());
            let value = if word == 1 && rng.index(2) == 0 {
                [
                    MCONTROL,
                    MCONTROL6,
                    MCONTROL | S_MODE_STORE,
                    MCONTROL6 | S_MODE_STORE,
                    u64::MAX,
                ][rng.index(5)]
            } else if rng.index(2) == 0 {
                BOUNDS[rng.index(BOUNDS.len())]
            } else {
                old ^ (1 << rng.index(64))
            };
            case.arena[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        3 => {
            let c = rng.index(case.calls.len());
            let fid = rng.index(8) as u64;
            case.calls[c] = if fid == 1 { shmem() } else { call(fid, [0; 6]) };
        }
        4 => {
            let c = rng.index(case.calls.len());
            case.calls[c].ptr_mask ^= 1 << rng.index(6);
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
        _ => return structured_case(rng),
    }
    case
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_dbtr_cases_are_replayable() {
        let mut rng = Rng::new(23);
        let mut case = initial_cases().remove(7);
        for _ in 0..500 {
            for next in [
                uniform_case(&mut rng),
                structured_case(&mut rng),
                mutate(&case, &mut rng),
            ] {
                assert!((1..=MAX_CALLS).contains(&next.calls.len()));
                assert_eq!(InputCase::from_bytes(&next.to_bytes(1)).unwrap(), next);
                case = next;
            }
        }
    }

    #[test]
    fn lifecycle_has_initialized_shared_memory_and_cleanup() {
        let case = lifecycle(MCONTROL6 | S_MODE_STORE);
        assert_eq!(case.calls.len(), MAX_CALLS);
        assert_eq!(case.calls[1].ptr_mask, 1);
        assert_eq!(case.calls[2].fid, 3);
        assert_eq!(case.calls[6].fid, 5);
        assert_eq!(case.calls[7], clear_shmem());
        assert_eq!(
            u64::from_le_bytes(case.arena[8..16].try_into().unwrap()),
            MCONTROL6 | S_MODE_STORE
        );
    }
}
