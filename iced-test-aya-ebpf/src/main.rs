#![no_std]
#![no_main]

use core::ptr;

use aya_ebpf::{
    bindings::{bpf_raw_tracepoint_args, pt_regs},
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, raw_tracepoint},
    maps::RingBuf,
    programs::RawTracePointContext,
    EbpfContext, PtRegs,
};
use aya_log_ebpf::{error, warn};
use iced_test_aya_common::Data;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 3, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn iced_test_aya(ctx: RawTracePointContext) -> i32 {
    match try_iced_test_aya(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// Args basically always contains 2 arguments: *pt_regs and op_code (syscall id).
/// See https://stackoverflow.com/questions/70652825/ebpf-raw-tracepoint-arguments
fn get_args(ctx: &RawTracePointContext) -> &[u64] {
    let args: &bpf_raw_tracepoint_args =
        unsafe { &*{ ctx.as_ptr() as *mut bpf_raw_tracepoint_args } };

    let args = unsafe { args.args.as_slice(2) };
    args
}

fn try_iced_test_aya(ctx: RawTracePointContext) -> Result<i32, i32> {
    // Get regs pointer and continue if op_code is execve (59).
    // See:
    // - https://github.com/torvalds/linux/blob/v6.7/arch/x86/entry/syscalls/syscall_64.tbl
    // - https://github.com/torvalds/linux/blob/v6.7/include/linux/syscalls.h
    let [regs, 59, ..] = get_args(&ctx) else {
        return Ok(0);
    };
    let regs = PtRegs::new(*regs as *mut _);

    let Some(mut entry) = EVENTS.reserve(0) else {
        error!(&ctx, "EVENTS RingBuf is full");
        return Ok(0);
    };

    unsafe {
        ptr::write_unaligned(
            entry.as_mut_ptr(),
            Data {
                uid: ctx.uid(),
                pid: ctx.pid(),
                command: ctx.command().unwrap_or(*b"ERR             "),
                // message: *b"Hello world",
                path: [0; 64],
            },
        );

        // Filename of the executed command is the first arg
        // See: https://elixir.bootlin.com/linux/v6.10.5/source/include/linux/syscalls.h#L800
        if let Some(src) = regs.arg(0) {
            let _ = bpf_probe_read_user_str_bytes(src, &mut (*entry.as_mut_ptr()).path);
        } else {
            warn!(&ctx, "Error getting arg0");
        }
    }
    entry.submit(0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
