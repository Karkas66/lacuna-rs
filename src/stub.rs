//
// stub.rs — JIT indirect-syscall stub emission for lacuna-rs
//
// Ported from lacuna_chain.c: alloc_stub().
//
// Two stub variants are emitted:
//
//  1. Ghost-gadget path (when g_ghost_gadget && func_sr):
//       mov [rsp+8], rbx          ; save callee-saved RBX
//       mov r10, rcx              ; Win64 syscall ABI
//       mov eax, <SSN>
//       lea rbx, [rip+Y]          ; &func_sr
//       mov r11, [rsp]            ; save real return addr
//       mov [rsp+16], r11         ; stash it
//       lea r11, [rip+W]          ; &epilogue
//       mov [rsp], r11            ; swap return addr -> epilogue
//       jmp [rip+V]               ; jmp [ghost_gadget]  -> JMP [RBX] -> syscall;ret
//       ; epilogue:
//       mov rbx, [rsp]            ; restore RBX
//       jmp [rsp+8]               ; jmp to original return
//       ; data:
//       dq ghost_gadget
//       dq func_sr
//
//  2. Direct path (no ghost gadget):
//       mov r10, rcx
//       mov eax, <SSN>
//       jmp [rip+0]               ; jmp [func_sr]   (if func_sr != 0)
//       dq func_sr
//     —or—
//       mov r10, rcx
//       mov eax, <SSN>
//       syscall                    ; (if func_sr == 0)
//       ret
//

#![allow(dead_code)]

use crate::win::{
    self, DWORD, ULONG64, PVOID, DWORD as ULONG,
    PAGE_EXECUTE_READ, PAGE_READWRITE, MEM_COMMIT, MEM_RESERVE,
};
use core::ptr;

pub struct Stub {
    pub code: PVOID,
}

impl Stub {
    pub fn as_fn(&self) -> PVOID {
        self.code
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        if !self.code.is_null() {
            unsafe {
                win::VirtualFree(self.code, 0, win::MEM_RELEASE);
            }
        }
    }
}

pub static G_GHOST_GADGET: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static G_GHOST_MOD: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);

pub fn make_stub(ssn: DWORD, func_sr: ULONG64) -> Option<Stub> {
    let mut code: [u8; 80] = [0; 80];
    let mut off = 0usize;

    let ghost_gadget = G_GHOST_GADGET.load(core::sync::atomic::Ordering::Relaxed);

    if ghost_gadget != 0 && func_sr != 0 {
        // ── Ghost-gadget path ───────────────────────────────────────────
        emit(&mut code, &mut off, &[0x48, 0x89, 0x5C, 0x24, 0x08]);  // mov [rsp+8], rbx
        emit(&mut code, &mut off, &[0x4C, 0x8B, 0xD1]);               // mov r10, rcx
        code[off] = 0xB8; off += 1;                                    // mov eax, imm32
        code[off..off + 4].copy_from_slice(&ssn.to_ne_bytes()); off += 4;
        emit(&mut code, &mut off, &[0x48, 0x8D, 0x1D]);               // lea rbx, [rip+disp32]
        let lea_rbx = off; off += 4;
        emit(&mut code, &mut off, &[0x4C, 0x8B, 0x1C, 0x24]);         // mov r11, [rsp]
        emit(&mut code, &mut off, &[0x4C, 0x89, 0x5C, 0x24, 0x10]);   // mov [rsp+16], r11
        emit(&mut code, &mut off, &[0x4C, 0x8D, 0x1D]);               // lea r11, [rip+disp32]
        let lea_r11 = off; off += 4;
        emit(&mut code, &mut off, &[0x4C, 0x89, 0x1C, 0x24]);         // mov [rsp], r11
        emit(&mut code, &mut off, &[0xFF, 0x25]);                     // jmp [rip+disp32]
        let jmp_disp = off; off += 4;
        let epilogue = off;
        emit(&mut code, &mut off, &[0x48, 0x8B, 0x1C, 0x24]);         // mov rbx, [rsp]
        emit(&mut code, &mut off, &[0xFF, 0x64, 0x24, 0x08]);         // jmp [rsp+8]
        let ghost_data = off;
        code[off..off + 8].copy_from_slice(&ghost_gadget.to_ne_bytes()); off += 8;
        let sr_data = off;
        code[off..off + 8].copy_from_slice(&func_sr.to_ne_bytes()); off += 8;
        patch_disp(&mut code, lea_rbx, sr_data);
        patch_disp(&mut code, lea_r11, epilogue);
        patch_disp(&mut code, jmp_disp, ghost_data);
    } else {
        // ── Direct path (simple jmp [func_sr]) ─────────────────────────
        emit(&mut code, &mut off, &[0x4C, 0x8B, 0xD1]);               // mov r10, rcx
        code[off] = 0xB8; off += 1;                                    // mov eax, imm32
        code[off..off + 4].copy_from_slice(&ssn.to_ne_bytes()); off += 4;

        if func_sr != 0 {
            emit(&mut code, &mut off, &[0xFF, 0x25]);                  // jmp [rip+0]
            code[off..off + 4].copy_from_slice(&0i32.to_ne_bytes()); off += 4;
            code[off..off + 8].copy_from_slice(&func_sr.to_ne_bytes()); off += 8;
        } else {
            emit(&mut code, &mut off, &[0x0F, 0x05, 0xC3]);           // syscall; ret
        }
    }

    let m = unsafe {
        win::VirtualAlloc(
            ptr::null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if m.is_null() {
        return None;
    }
    unsafe {
        ptr::copy_nonoverlapping(code.as_ptr(), m as *mut u8, off);
        let mut old: ULONG = 0;
        win::VirtualProtect(m, 0x1000, PAGE_EXECUTE_READ, &mut old);
    }
    Some(Stub { code: m })
}

#[inline]
fn emit(code: &mut [u8; 80], off: &mut usize, bytes: &[u8]) {
    let n = bytes.len();
    code[*off..*off + n].copy_from_slice(bytes);
    *off += n;
}

#[inline]
fn patch_disp(code: &mut [u8; 80], disp_off: usize, target: usize) {
    let disp = (target as i64 - (disp_off as i64 + 4)) as i32;
    code[disp_off..disp_off + 4].copy_from_slice(&disp.to_ne_bytes());
}