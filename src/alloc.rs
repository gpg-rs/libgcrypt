// Based on code from liballoc_system/lib.rs
use std::cmp;
use std::heap::{Alloc, AllocErr, Layout};
use std::ptr;

use ffi;

#[cfg(all(any(target_arch = "x86", target_arch = "arm", target_arch = "mips",
              target_arch = "powerpc", target_arch = "powerpc64", target_arch = "asmjs",
              target_arch = "wasm32")))]
const MIN_ALIGN: usize = 8;
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "mips64",
              target_arch = "s390x", target_arch = "sparc64")))]
const MIN_ALIGN: usize = 16;

#[repr(C)]
struct Header(*mut u8);

unsafe fn get_header<'a>(ptr: *mut u8) -> &'a mut Header {
    &mut *(ptr as *mut Header).offset(-1)
}

unsafe fn align_pointer(ptr: *mut u8, align: usize) -> *mut u8 {
    let aligned = ptr.offset((align - ((ptr as usize) & (align - 1))) as isize);
    *get_header(aligned) = Header(ptr);
    aligned
}

#[derive(Debug, Copy, Clone)]
pub struct SecureAllocator {
    _priv: (),
}

impl Default for SecureAllocator {
    fn default() -> Self {
        ::init(|x| {
            let _ = x.enable_secure_rndpool().enable_secmem(1);
        });
        SecureAllocator { _priv: () }
    }
}

unsafe impl Alloc for SecureAllocator {
    #[inline]
    unsafe fn alloc(&mut self, request: Layout) -> Result<*mut u8, AllocErr> {
        (&*self).alloc(request)
    }

    #[inline]
    unsafe fn alloc_zeroed(&mut self, request: Layout) -> Result<*mut u8, AllocErr> {
        (&*self).alloc_zeroed(request)
    }

    #[inline]
    unsafe fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        (&*self).dealloc(ptr, layout)
    }

    #[inline]
    unsafe fn realloc(
        &mut self, ptr: *mut u8, old_layout: Layout, new_layout: Layout
    ) -> Result<*mut u8, AllocErr> {
        (&*self).realloc(ptr, old_layout, new_layout)
    }
}

unsafe impl<'a> Alloc for &'a SecureAllocator {
    #[inline]
    unsafe fn alloc(&mut self, request: Layout) -> Result<*mut u8, AllocErr> {
        let ptr = if request.align() <= MIN_ALIGN {
            ffi::gcry_malloc_secure(request.size()) as *mut u8
        } else {
            // Since all valid pointers have an alignment of at least MIN_ALIGN there will always
            // be at least MIN_ALIGN bytes before the aligned pointer and therefore enough space
            // for the header assuming size_of::<usize>() <= MIN_ALIGN
            let size = request.size() + request.align();
            let ptr = ffi::gcry_malloc_secure(size) as *mut u8;
            if !ptr.is_null() {
                align_pointer(ptr, request.align())
            } else {
                ptr
            }
        };
        if !ptr.is_null() {
            Ok(ptr)
        } else {
            Err(AllocErr::Exhausted { request })
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&mut self, request: Layout) -> Result<*mut u8, AllocErr> {
        if request.align() <= MIN_ALIGN {
            let ptr = ffi::gcry_calloc_secure(1, request.size());
            if !ptr.is_null() {
                Ok(ptr as *mut _)
            } else {
                Err(AllocErr::Exhausted { request })
            }
        } else {
            let ptr = self.alloc(request.clone())?;
            ptr::write_bytes(ptr, 0, request.size());
            Ok(ptr)
        }
    }

    #[inline]
    unsafe fn dealloc(&mut self, mut ptr: *mut u8, layout: Layout) {
        if layout.align() > MIN_ALIGN {
            ptr = (*get_header(ptr)).0;
        }
        ffi::gcry_free(ptr as *mut _);
    }

    #[inline]
    unsafe fn realloc(
        &mut self, ptr: *mut u8, old_layout: Layout, new_layout: Layout
    ) -> Result<*mut u8, AllocErr> {
        if old_layout.align() != new_layout.align() {
            return Err(AllocErr::Unsupported {
                details: "cannot change alignment on `realloc`",
            });
        }

        if new_layout.align() <= MIN_ALIGN {
            let ptr = ffi::gcry_realloc(ptr as *mut _, new_layout.size());
            if !ptr.is_null() {
                Ok(ptr as *mut _)
            } else {
                Err(AllocErr::Exhausted {
                    request: new_layout,
                })
            }
        } else {
            let new_ptr = self.alloc(new_layout.clone())?;
            let size = cmp::min(old_layout.size(), new_layout.size());
            ptr::copy_nonoverlapping(ptr, new_ptr, size);
            self.dealloc(ptr, old_layout);
            Ok(new_ptr)
        }
    }
}
