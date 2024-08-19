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
use aya_log_ebpf::warn;
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

fn get_args(ctx: &RawTracePointContext) -> &[u64] {
    let args: &bpf_raw_tracepoint_args =
        unsafe { &*{ ctx.as_ptr() as *mut bpf_raw_tracepoint_args } };

    let args = unsafe { args.args.as_slice(2) };
    args
}

fn try_iced_test_aya(ctx: RawTracePointContext) -> Result<i32, i32> {
    let args = get_args(&ctx);

    let [args, op, ..] = args else {
        return Ok(0);
    };

    if op != &59 {
        return Ok(0);
    }

    let args: *mut pt_regs = *args as *mut _;
    let args = PtRegs::new(args);

    // let args = get_args::<3>(&ctx);
    // let [_, _, arg, ..] = args else {
    //     return Ok(0);
    // };

    let Some(mut entry) = EVENTS.reserve(0) else {
        warn!(&ctx, "Error");
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

        let Some(src) = args.arg(0) else {
            warn!(&ctx, "Error getting arg0");
            entry.discard(0);
            return Ok(0);
        };
        let _ = bpf_probe_read_user_str_bytes(src, &mut (*entry.as_mut_ptr()).path);
    }
    entry.submit(0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
