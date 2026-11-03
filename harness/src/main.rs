#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

const INPUT_BASE: usize = 0x8800_0000;
const CALLS_OFFSET: usize = 16;
const CALL_SIZE: usize = 72;
const ARENA_OFFSET: usize = 1024;
const MAX_CALLS: usize = 8;
const DBTR: u64 = 0x4442_5452;
const UART: usize = 0x1000_0000;
const SYSCON: usize = 0x0010_0000;

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        "la sp, __stack_top",
        "la t0, __bss_start",
        "la t1, __bss_end",
        "1:",
        "bgeu t0, t1, 2f",
        "sd zero, 0(t0)",
        "addi t0, t0, 8",
        "j 1b",
        "2:",
        "j {entry}",
        entry = sym rust_main,
    );
}

#[unsafe(naked)]
#[unsafe(link_section = ".text.trap")]
extern "C" fn trap_entry() -> ! {
    naked_asm!(
        "la sp, __stack_top",
        "csrr a0, scause",
        "csrr a1, stval",
        "csrr a2, sepc",
        "j {handler}",
        handler = sym report_trap,
    );
}

#[inline(never)]
extern "C" fn report_trap(cause: u64, tval: u64, pc: u64) -> ! {
    put_str("\nHISAME:TRAP:");
    put_hex(read_u64(INPUT_BASE + 8));
    put_byte(b':');
    put_hex(cause);
    put_byte(b':');
    put_hex(tval);
    put_byte(b':');
    put_hex(pc);
    put_byte(b'\n');
    shutdown()
}

#[unsafe(no_mangle)]
extern "C" fn rust_main(hart_id: usize, _dtb: usize) -> ! {
    if hart_id != 0 {
        loop {
            unsafe { asm!("wfi") };
        }
    }
    unsafe { asm!("csrw stvec, {addr}", addr = in(reg) trap_entry as *const () as usize) };

    if read_u32(INPUT_BASE) != u32::from_le_bytes(*b"HSM1") || read_byte(INPUT_BASE + 5) != 1 {
        put_str("\nHISAME:NO_INPUT\n");
        shutdown();
    }

    let count = read_byte(INPUT_BASE + 4) as usize;
    let nonce = read_u64(INPUT_BASE + 8);
    if count == 0 || count > MAX_CALLS {
        put_str("\nHISAME:BAD_COUNT\n");
        shutdown();
    }
    put_str("\nHISAME:BEGIN:");
    put_hex(nonce);
    put_byte(b'\n');

    for index in 0..count {
        let base = INPUT_BASE + CALLS_OFFSET + index * CALL_SIZE;
        let eid = read_u64(base);
        let fid = read_u64(base + 8);
        let mask = read_byte(base + 64);
        let mut args = [0u64; 6];
        for (n, arg) in args.iter_mut().enumerate() {
            let value = read_u64(base + 16 + n * 8);
            *arg = if mask & (1 << n) != 0 {
                (INPUT_BASE + ARENA_OFFSET).wrapping_add(value as usize) as u64
            } else {
                value
            };
        }
        let (error, value) = ecall(eid, fid, args);
        put_str("\nHISAME:RESULT:");
        put_hex(nonce);
        put_byte(b':');
        put_hex(index as u64);
        put_byte(b':');
        put_hex(error);
        put_byte(b':');
        put_hex(value);
        put_byte(b'\n');
        if eid == DBTR {
            put_str("HISAME:ARENA:");
            put_hex(nonce);
            put_byte(b':');
            put_hex(index as u64);
            for word in 0..4 {
                put_byte(b':');
                put_hex(read_u64(INPUT_BASE + ARENA_OFFSET + word * 8));
            }
            put_byte(b'\n');
        }
    }
    put_str("\nHISAME:DONE:");
    put_hex(nonce);
    put_byte(b':');
    put_hex(count as u64);
    put_byte(b'\n');
    shutdown()
}

#[inline(never)]
fn ecall(eid: u64, fid: u64, args: [u64; 6]) -> (u64, u64) {
    let mut a0 = args[0];
    let mut a1 = args[1];
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0,
            inlateout("a1") a1,
            in("a2") args[2],
            in("a3") args[3],
            in("a4") args[4],
            in("a5") args[5],
            in("a6") fid,
            in("a7") eid,
            options(nostack),
        );
    }
    (a0, a1)
}

fn read_byte(addr: usize) -> u8 {
    unsafe { read_volatile(addr as *const u8) }
}

fn read_u32(addr: usize) -> u32 {
    let mut bytes = [0u8; 4];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = read_byte(addr + i);
    }
    u32::from_le_bytes(bytes)
}

fn read_u64(addr: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = read_byte(addr + i);
    }
    u64::from_le_bytes(bytes)
}

fn put_byte(byte: u8) {
    while read_byte(UART + 5) & 0x20 == 0 {}
    unsafe { write_volatile(UART as *mut u8, byte) };
}

fn put_str(message: &str) {
    for byte in message.bytes() {
        put_byte(byte);
    }
}

fn put_hex(value: u64) {
    for shift in (0..16).rev() {
        let digit = ((value >> (shift * 4)) & 15) as u8;
        put_byte(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
    }
}

fn shutdown() -> ! {
    unsafe { write_volatile(SYSCON as *mut u32, 0x5555) };
    loop {
        unsafe { asm!("wfi") };
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    put_str("\nHISAME:PANIC\n");
    shutdown()
}
