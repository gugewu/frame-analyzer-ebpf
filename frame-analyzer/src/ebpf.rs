/*
 * Copyright (c) 2024 shadow3aaa@gitbub.com
 *
 * This file is part of frame-analyzer-ebpf.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use aya::{Ebpf, include_bytes_aligned};
use ctor::ctor;

use crate::error::Result;

#[ctor]
fn ebpf_workround() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const rlim) };
}

pub fn load_bpf() -> Result<Ebpf> {
    // This will include eBPF object file as raw bytes at compile-time and load it at runtime.
    // 路径由 build.rs 通过 `cargo:rustc-env=FRAME_ANALYZER_EBPF_PATH=...` 注入，
    // 这样在交叉编译（host 与 target 的 OUT_DIR 不同）时也能正确找到 eBPF 二进制。
    let bpf = Ebpf::load(include_bytes_aligned!(env!("FRAME_ANALYZER_EBPF_PATH")))?;

    Ok(bpf)
}
