#include "syscall/syscall_internal.h"
#include "sched/thread.h"
#include "sched/sched.h"
#include "mm/pmm.h"
#include "mm/vmm.h"
#include "mm/swap.h"
#include "ipc/agent_ns.h"
#include "arch/serial.h"
#include "arch/timer.h"
#include "arch/frame.h"

#include "arch/paging.h"

static inline void flush_page(uint64_t addr) {
    arch_flush_tlb_page(addr);
}

int64_t sys_mmap(uint64_t addr_hint, uint64_t length,
                          uint64_t prot, uint64_t flags, uint64_t fd) {
    (void)fd;
    /* Linux mmap: (addr, length, prot, flags, fd, offset)
     * For anonymous private mappings (the common case for malloc/TLS):
     * addr=0, length=bytes, flags=MAP_PRIVATE|MAP_ANONYMOUS */
    #define MAP_FIXED 0x10

    uint64_t num_pages;
    if (length == 0)
        return -EINVAL;
    /* If length looks like a page count (old Limnx API compat: small number, no flags) */
    if (length <= MMAP_MAX_PAGES && flags == 0) {
        num_pages = length;  /* old API: sys_mmap(num_pages) */
    } else {
        num_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    }
    if (num_pages == 0 || num_pages > MMAP_MAX_PAGES)
        return -EINVAL;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    /* MAP_FIXED with PROT_NONE: guard page — just return the address.
     * We don't actually need to unmap or change protections since
     * the page might not be mapped yet, and we don't enforce PROT_NONE. */
    if ((flags & MAP_FIXED) && prot == 0) {
        /* musl uses this for brk guard pages. Just acknowledge it. */
        return (int64_t)addr_hint;
    }

    /* MAP_FIXED: use the provided address instead of mmap_next_addr */
    int use_fixed = (flags & MAP_FIXED) && addr_hint != 0;

    /* Check memory rlimit */
    if (proc->rlimit_mem_pages > 0 &&
        proc->used_mem_pages + num_pages > proc->rlimit_mem_pages)
        return -ENOMEM;

    /* Find a free mmap slot */
    int slot = -1;
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (!proc->mmap_table[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        return -1;

    /* Allocate pages individually (don't need physical contiguity for mmap) */
    uint64_t virt = use_fixed ? (addr_hint & ~(PAGE_SIZE - 1)) : proc->mmap_next_addr;
    uint64_t first_phys = 0;
    for (uint64_t i = 0; i < num_pages; i++) {
        uint64_t page_phys = pmm_alloc_page();
        if (page_phys == 0) return -ENOMEM;
        if (i == 0) first_phys = page_phys;
        uint64_t page_virt = virt + i * PAGE_SIZE;

        /* Zero the page */
        uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(page_phys);
        for (uint64_t j = 0; j < PAGE_SIZE; j++)
            dst[j] = 0;

        if (vmm_map_page_in(proc->cr3, page_virt, page_phys,
                            PTE_USER | PTE_WRITABLE | PTE_NX) != 0) {
            pmm_free_page(page_phys);
            return -ENOMEM;
        }
    }

    /* Record the mapping (phys_addr is first page only — pages may not be contiguous) */
    proc->mmap_table[slot].virt_addr = virt;
    proc->mmap_table[slot].phys_addr = first_phys;
    proc->mmap_table[slot].num_pages = (uint32_t)num_pages;
    proc->mmap_table[slot].used = 1;
    proc->mmap_table[slot].shm_id = -1;
    proc->mmap_table[slot].vfs_node = -1;
    proc->mmap_table[slot].file_offset = 0;

    /* Bump next address (+1 guard gap page) — only for non-fixed mappings */
    if (!use_fixed)
        proc->mmap_next_addr = virt + (num_pages + 1) * PAGE_SIZE;
    proc->used_mem_pages += num_pages;

    return (int64_t)virt;
}

int64_t sys_munmap(uint64_t virt_addr, uint64_t a2,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    /* Find the mmap entry */
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (proc->mmap_table[i].used &&
            proc->mmap_table[i].virt_addr == virt_addr) {
            uint32_t npages = proc->mmap_table[i].num_pages;
            uint64_t phys = proc->mmap_table[i].phys_addr;

            if (proc->mmap_table[i].shm_id >= 0) {
                /* Shared memory: clear PTEs + flush TLB, then decrement ref */
                for (uint32_t j = 0; j < npages; j++) {
                    uint64_t va = virt_addr + (uint64_t)j * PAGE_SIZE;
                    uint64_t *pte = vmm_get_pte(proc->cr3, va);
                    if (pte && (*pte & PTE_PRESENT)) {
                        *pte = 0;
                        flush_page(va);
                    }
                }
                int32_t sid = proc->mmap_table[i].shm_id;
                uint64_t sflags;
                shm_lock_acquire(&sflags);
                if (sid < MAX_SHM_REGIONS && shm_table[sid].ref_count > 0) {
                    shm_table[sid].ref_count--;
                    if (shm_table[sid].ref_count == 0) {
                        for (uint32_t pi = 0; pi < shm_table[sid].num_pages; pi++) {
                            if (shm_table[sid].phys_pages[pi]) {
                                pmm_free_page(shm_table[sid].phys_pages[pi]);
                                shm_table[sid].phys_pages[pi] = 0;
                            }
                        }
                        shm_table[sid].key = -1;
                        shm_table[sid].num_pages = 0;
                    }
                }
                shm_unlock_release(sflags);
            } else {
                /* Private mapping: clear PTEs, flush TLB, free physical pages */
                for (uint32_t j = 0; j < npages; j++) {
                    uint64_t va = virt_addr + (uint64_t)j * PAGE_SIZE;
                    uint64_t *pte = vmm_get_pte(proc->cr3, va);
                    if (pte && (*pte & PTE_PRESENT)) {
                        uint64_t page_phys = *pte & PTE_ADDR_MASK;
                        *pte = 0;
                        flush_page(va);
                        pmm_free_page(page_phys);
                    } else {
                        /* Fallback: page not in PTE (demand-paged, never faulted) */
                        if (phys)
                            pmm_free_page(phys + (uint64_t)j * PAGE_SIZE);
                    }
                }
            }

            proc->mmap_table[i].used = 0;
            proc->mmap_table[i].shm_id = -1;
            if (proc->used_mem_pages >= npages)
                proc->used_mem_pages -= npages;
            return 0;
        }
    }

    return -1;
}

int64_t sys_fmmap(uint64_t fd, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    if (fd >= MAX_FDS)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc)
        return -1;

    fd_entry_t *entry = &proc->fd_table[fd];
    if (entry->node == NULL)
        return -1;

    vfs_node_t *node = entry->node;
    uint64_t file_size = node->size;
    if (file_size == 0)
        return -1;


    /* Allocate mmap pages */
    uint64_t num_pages = (file_size + PAGE_SIZE - 1) / PAGE_SIZE;
    if (num_pages > MMAP_MAX_PAGES)
        return -1;

    /* Find a free mmap slot */
    int slot = -1;
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (!proc->mmap_table[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        return -1;

    int node_idx = vfs_node_index(node);
    if (node_idx < 0)
        return -1;

    /* Allocate pages and populate from file data.
     * Uses batched reads: allocate BATCH_PAGES contiguous physical pages,
     * read a large chunk into them via VFS, then map individually.
     * Falls back to per-page allocation if contiguous alloc fails. */
    #define FMMAP_BATCH_PAGES 64  /* 256KB per batch */
    uint64_t virt = proc->mmap_next_addr;
    uint64_t i = 0;

    /* Progress reporting for large mmaps */
    uint64_t progress_interval = num_pages / 10;  /* every 10% */
    if (progress_interval < FMMAP_BATCH_PAGES) progress_interval = FMMAP_BATCH_PAGES;
    int show_progress = (num_pages > 1024);  /* >4MB */
    if (show_progress)
        serial_printf("[fmmap] loading %s (%lu MB)...\n",
                      node->name, (unsigned long)(file_size / (1024 * 1024)));

    while (i < num_pages) {
        /* Yield periodically so other processes can run during large loads */
        if (i > 0 && (i % (FMMAP_BATCH_PAGES * 16)) == 0)
            sched_yield();

        /* Progress indicator */
        if (show_progress && i > 0 && (i % progress_interval) < FMMAP_BATCH_PAGES)
            serial_printf("[fmmap] %lu%%\n",
                          (unsigned long)(i * 100 / num_pages));

        uint64_t remain = num_pages - i;
        uint32_t batch = (remain > FMMAP_BATCH_PAGES) ? FMMAP_BATCH_PAGES : (uint32_t)remain;

        /* Try contiguous allocation for the batch */
        uint64_t batch_phys = pmm_alloc_contiguous(batch);
        if (batch_phys == 0) {
            /* Fall back to single page */
            batch = 1;
            batch_phys = pmm_alloc_page();
            if (batch_phys == 0) goto fail_cleanup;
        }

        /* Read file data into the contiguous physical buffer via HHDM */
        uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(batch_phys);
        uint64_t offset = i * PAGE_SIZE;
        uint64_t read_len = (uint64_t)batch * PAGE_SIZE;
        uint64_t avail = file_size - offset;
        if (read_len > avail) read_len = avail;

        int64_t got = vfs_read(node_idx, offset, dst, read_len);
        if (got < 0) got = 0;
        /* Zero remainder */
        for (uint64_t j = (uint64_t)got; j < (uint64_t)batch * PAGE_SIZE; j++)
            dst[j] = 0;

        /* Map each page individually into user address space */
        for (uint32_t b = 0; b < batch; b++) {
            uint64_t page_phys = batch_phys + (uint64_t)b * PAGE_SIZE;
            uint64_t page_virt = virt + (i + b) * PAGE_SIZE;

            if (vmm_map_page_in(proc->cr3, page_virt, page_phys,
                                PTE_USER | PTE_WRITABLE | PTE_NX) != 0) {
                /* Free this batch's remaining pages */
                for (uint32_t f = b; f < batch; f++)
                    pmm_free_page(batch_phys + (uint64_t)f * PAGE_SIZE);
                goto fail_cleanup;
            }
        }
        i += batch;
    }

    goto fmmap_done;

fail_cleanup:
    for (uint64_t k = 0; k < i; k++) {
        uint64_t kv = virt + k * PAGE_SIZE;
        uint64_t *pte = vmm_get_pte(proc->cr3, kv);
        if (pte && (*pte & PTE_PRESENT)) {
            uint64_t kp = *pte & PTE_ADDR_MASK;
            *pte = 0;
            pmm_free_page(kp);
        }
    }
    return -1;

fmmap_done:
    if (show_progress)
        serial_printf("[fmmap] done (%lu pages mapped)\n", (unsigned long)num_pages);

    /* Record the mapping (phys_addr=0 since pages are non-contiguous) */
    proc->mmap_table[slot].virt_addr = virt;
    proc->mmap_table[slot].phys_addr = 0;
    proc->mmap_table[slot].num_pages = (uint32_t)num_pages;
    proc->mmap_table[slot].used = 1;
    proc->mmap_table[slot].shm_id = -1;
    proc->mmap_table[slot].vfs_node = -1;
    proc->mmap_table[slot].file_offset = 0;
    proc->mmap_next_addr = virt + (num_pages + 1) * PAGE_SIZE;

    return (int64_t)virt;
}

int64_t sys_shmget(uint64_t key, uint64_t num_pages,
                            uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    if (num_pages == 0 || num_pages > 16)
        return -1;

    uint64_t sflags;
    shm_lock_acquire(&sflags);

    /* Search for existing key match */
    for (int i = 0; i < MAX_SHM_REGIONS; i++) {
        if (shm_table[i].key == (int32_t)key) {
            shm_unlock_release(sflags);
            return i;
        }
    }

    /* Allocate new region */
    int slot = -1;
    for (int i = 0; i < MAX_SHM_REGIONS; i++) {
        if (shm_table[i].key == -1) { slot = i; break; }
    }
    if (slot < 0) { shm_unlock_release(sflags); return -1; }

    /* Mark slot as taken before releasing lock for page allocation */
    shm_table[slot].key = (int32_t)key;
    shm_table[slot].num_pages = (uint32_t)num_pages;
    shm_table[slot].ref_count = 0;
    shm_unlock_release(sflags);

    /* Allocate physical pages individually (outside lock — pmm has its own) */
    for (uint32_t i = 0; i < (uint32_t)num_pages; i++) {
        uint64_t pg = pmm_alloc_page();
        if (pg == 0) {
            /* Free already allocated */
            for (uint32_t j = 0; j < i; j++)
                pmm_free_page(shm_table[slot].phys_pages[j]);
            shm_lock_acquire(&sflags);
            shm_table[slot].key = -1;
            shm_unlock_release(sflags);
            return -1;
        }
        /* Zero the page */
        uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(pg);
        for (uint64_t j = 0; j < PAGE_SIZE; j++)
            dst[j] = 0;
        shm_table[slot].phys_pages[i] = pg;
    }

    return slot;
}

int64_t sys_shmat(uint64_t shmid, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    uint64_t sflags;
    shm_lock_acquire(&sflags);
    if (shmid >= MAX_SHM_REGIONS || shm_table[shmid].key == -1) {
        shm_unlock_release(sflags);
        return 0;
    }

    uint32_t npages = shm_table[shmid].num_pages;
    uint64_t phys_pages_copy[16];
    for (uint32_t i = 0; i < npages; i++)
        phys_pages_copy[i] = shm_table[shmid].phys_pages[i];
    shm_unlock_release(sflags);

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return 0;

    /* Find a free mmap slot */
    int slot = -1;
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (!proc->mmap_table[i].used) { slot = i; break; }
    }
    if (slot < 0) return 0;

    uint64_t virt = proc->mmap_next_addr;

    /* Map each page individually and increment refcount for PTE reference */
    for (uint32_t i = 0; i < npages; i++) {
        uint64_t page_phys = phys_pages_copy[i];
        uint64_t page_virt = virt + (uint64_t)i * PAGE_SIZE;
        if (vmm_map_page_in(proc->cr3, page_virt, page_phys,
                            PTE_USER | PTE_WRITABLE | PTE_NX) != 0)
            return 0;
        pmm_ref_inc(page_phys);
    }

    proc->mmap_table[slot].virt_addr = virt;
    proc->mmap_table[slot].phys_addr = phys_pages_copy[0];
    proc->mmap_table[slot].num_pages = npages;
    proc->mmap_table[slot].used = 1;
    proc->mmap_table[slot].shm_id = (int32_t)shmid;
    proc->mmap_table[slot].vfs_node = -1;
    proc->mmap_table[slot].file_offset = 0;
    proc->mmap_next_addr = virt + (uint64_t)(npages + 1) * PAGE_SIZE;

    shm_lock_acquire(&sflags);
    shm_table[shmid].ref_count++;
    shm_unlock_release(sflags);

    return (int64_t)virt;
}

int64_t sys_shmdt(uint64_t virt_addr, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (proc->mmap_table[i].used &&
            proc->mmap_table[i].virt_addr == virt_addr &&
            proc->mmap_table[i].shm_id >= 0) {
            int32_t sid = proc->mmap_table[i].shm_id;
            uint32_t npages = proc->mmap_table[i].num_pages;
            {
                uint64_t sflags;
                shm_lock_acquire(&sflags);
                if (sid < MAX_SHM_REGIONS && shm_table[sid].ref_count > 0) {
                    shm_table[sid].ref_count--;
                    if (shm_table[sid].ref_count == 0) {
                        for (uint32_t pi = 0; pi < shm_table[sid].num_pages; pi++) {
                            if (shm_table[sid].phys_pages[pi]) {
                                pmm_free_page(shm_table[sid].phys_pages[pi]);
                                shm_table[sid].phys_pages[pi] = 0;
                            }
                        }
                        shm_table[sid].key = -1;
                        shm_table[sid].num_pages = 0;
                    }
                }
                shm_unlock_release(sflags);
            }
            /* Unmap pages from page table, flush TLB, drop PTE refcount */
            for (uint32_t p = 0; p < npages; p++) {
                uint64_t pv = virt_addr + (uint64_t)p * PAGE_SIZE;
                uint64_t *pte = vmm_get_pte(proc->cr3, pv);
                if (pte && (*pte & PTE_PRESENT)) {
                    uint64_t phys = *pte & PTE_ADDR_MASK;
                    *pte = 0;
                    flush_page(pv);
                    pmm_free_page(phys);
                }
            }
            proc->mmap_table[i].used = 0;
            proc->mmap_table[i].shm_id = -1;
            return 0;
        }
    }
    return -1;
}

int64_t sys_mmap2(uint64_t num_pages, uint64_t mmap_flags,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a3; (void)a4; (void)a5;

    if (num_pages == 0 || num_pages > MMAP_MAX_PAGES)
        return -EINVAL;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    /* Check memory rlimit */
    if (proc->rlimit_mem_pages > 0 &&
        proc->used_mem_pages + num_pages > proc->rlimit_mem_pages)
        return -ENOMEM;

    /* Namespace memory quota check */
    if (!agent_ns_quota_check(proc->ns_id, NS_QUOTA_MEM_PAGES, (uint32_t)num_pages))
        return -ENOMEM;

    /* Find a free mmap slot */
    int slot = -1;
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (!proc->mmap_table[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return -ENOMEM;

    uint64_t virt = proc->mmap_next_addr;

    if (mmap_flags & MMAP_DEMAND) {
        /* Demand-paged: reserve address space but don't allocate physical pages */
        proc->mmap_table[slot].virt_addr = virt;
        proc->mmap_table[slot].phys_addr = 0;
        proc->mmap_table[slot].num_pages = (uint32_t)num_pages;
        proc->mmap_table[slot].used = 1;
        proc->mmap_table[slot].shm_id = -1;
        proc->mmap_table[slot].demand = 1;
        proc->mmap_table[slot].vfs_node = -1;
        proc->mmap_table[slot].file_offset = 0;
        proc->mmap_next_addr = virt + (num_pages + 1) * 4096;
        proc->used_mem_pages += num_pages;
        return (int64_t)virt;
    }

    /* Eager allocation — same as sys_mmap */
    uint64_t phys = pmm_alloc_contiguous((uint32_t)num_pages);
    if (phys == 0) return -ENOMEM;

    for (uint64_t i = 0; i < num_pages; i++) {
        uint64_t page_phys = phys + i * 4096;
        uint64_t page_virt = virt + i * 4096;
        uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(page_phys);
        for (int j = 0; j < 4096; j++) dst[j] = 0;
        if (vmm_map_page_in(proc->cr3, page_virt, page_phys,
                            PTE_USER | PTE_WRITABLE | PTE_NX) != 0)
            return -ENOMEM;
    }

    proc->mmap_table[slot].virt_addr = virt;
    proc->mmap_table[slot].phys_addr = phys;
    proc->mmap_table[slot].num_pages = (uint32_t)num_pages;
    proc->mmap_table[slot].used = 1;
    proc->mmap_table[slot].shm_id = -1;
    proc->mmap_table[slot].demand = 0;
    proc->mmap_table[slot].vfs_node = -1;
    proc->mmap_table[slot].file_offset = 0;
    proc->mmap_next_addr = virt + (num_pages + 1) * 4096;
    proc->used_mem_pages += num_pages;
    return (int64_t)virt;
}

int64_t sys_mmap_file(uint64_t fd, uint64_t offset,
                              uint64_t num_pages, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;
    if (fd >= MAX_FDS || num_pages == 0 || num_pages > MMAP_MAX_PAGES)
        return -1;

    thread_t *t = thread_get_current();
    process_t *proc = t->process;
    if (!proc) return -1;

    fd_entry_t *entry = &proc->fd_table[fd];
    if (entry->node == NULL) return -1;

    vfs_node_t *node = entry->node;
    int node_idx = vfs_node_index(node);
    if (node_idx < 0) return -1;

    /* Find free mmap slot */
    int slot = -1;
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (!proc->mmap_table[i].used) { slot = i; break; }
    }
    if (slot < 0) return -12;  /* -ENOMEM */

    uint64_t virt = proc->mmap_next_addr;

    /* Reserve virtual address space — no physical pages allocated */
    proc->mmap_table[slot].virt_addr = virt;
    proc->mmap_table[slot].phys_addr = 0;
    proc->mmap_table[slot].num_pages = (uint32_t)num_pages;
    proc->mmap_table[slot].used = 1;
    proc->mmap_table[slot].shm_id = -1;
    proc->mmap_table[slot].demand = 1;
    proc->mmap_table[slot].vfs_node = (int32_t)node_idx;
    proc->mmap_table[slot].file_offset = offset;
    proc->mmap_next_addr = virt + (num_pages + 1) * PAGE_SIZE;

    return (int64_t)virt;
}

int64_t sys_mprotect(uint64_t virt_addr, uint64_t length,
                             uint64_t prot, uint64_t a4, uint64_t a5) {
    (void)a4; (void)a5;

    thread_t *t = thread_get_current();
    process_t *proc = t ? t->process : NULL;
    if (!proc) return -EINVAL;

    if (virt_addr & 0xFFF) return -EINVAL;  /* not page-aligned */
    if (length == 0) return -EINVAL;
    /* Bound both values so range_end below cannot wrap around and let a
     * huge length pass the mmap-entry check. */
    if (virt_addr >= USER_ADDR_MAX || length > USER_ADDR_MAX - virt_addr)
        return -EINVAL;

    /* Linux mprotect takes length in bytes, convert to pages */
    uint64_t num_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    uint64_t range_end = virt_addr + num_pages * PAGE_SIZE;

    /* Validate: entire range must be within a single mmap entry */
    int found = 0;
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (!proc->mmap_table[i].used) continue;
        uint64_t entry_start = proc->mmap_table[i].virt_addr;
        uint64_t entry_end = entry_start + (uint64_t)proc->mmap_table[i].num_pages * PAGE_SIZE;
        if (virt_addr >= entry_start && range_end <= entry_end) {
            found = 1;
            break;
        }
    }
    if (!found) return -EINVAL;

    /* Walk PTEs and update flags */
    for (uint64_t pg = 0; pg < num_pages; pg++) {
        uint64_t va = virt_addr + pg * PAGE_SIZE;
        uint64_t *pte = vmm_get_pte(proc->cr3, va);
        if (!pte) continue;  /* demand page not yet faulted — skip */
        if (swap_is_entry(*pte)) {
            /* A swap PTE holds a slot number, not a physical address.
             * Bring the page back before rewriting its flags; otherwise the
             * slot number would be mapped as a physical page. */
            if (swap_in(proc->cr3, va) != 0)
                return -ENOMEM;
            pte = vmm_get_pte(proc->cr3, va);
            if (!pte) return -ENOMEM;
        }
        uint64_t old = *pte;
        if (!(old & PTE_PRESENT)) continue;  /* not mapped yet */

        uint64_t phys = old & PTE_ADDR_MASK;
        /* Start from the existing entry so arch-specific bits (on ARM64 the
         * descriptor type, access flag, shareability and memory attributes)
         * are kept, and change only the permission bits. */
        uint64_t flags = old & ~PTE_ADDR_MASK;
        if (prot == PROT_NONE) {
            flags &= ~PTE_PRESENT;  /* page inaccessible */
        } else {
            flags = (prot & PROT_EXEC) ? (flags & ~PTE_NX) : (flags | PTE_NX);
            if (flags & PTE_COW) {
                /* COW page: keep it read-only so the fault handler still
                 * copies it; WAS_WRITABLE tells that handler whether the
                 * write may then be granted. */
                flags = PTE_MAKE_READONLY(flags);
                if (prot & PROT_WRITE)
                    flags |= PTE_WAS_WRITABLE;
                else
                    flags &= ~PTE_WAS_WRITABLE;
            } else if (prot & PROT_WRITE) {
                flags = PTE_MAKE_WRITABLE(flags);
            } else {
                flags = PTE_MAKE_READONLY(flags);
            }
        }

        *pte = phys | flags;
        flush_page(va);
    }

    return 0;
}

int64_t sys_mmap_guard(uint64_t num_pages, uint64_t a2,
                               uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;

    if (num_pages == 0 || num_pages > MMAP_MAX_PAGES)
        return -EINVAL;

    thread_t *t = thread_get_current();
    process_t *proc = t ? t->process : NULL;
    if (!proc) return -EINVAL;

    if (proc->rlimit_mem_pages > 0 &&
        proc->used_mem_pages + num_pages > proc->rlimit_mem_pages)
        return -ENOMEM;

    int slot = -1;
    for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
        if (!proc->mmap_table[i].used) { slot = i; break; }
    }
    if (slot < 0) return -ENOMEM;

    uint64_t phys = pmm_alloc_contiguous((uint32_t)num_pages);
    if (phys == 0) return -ENOMEM;

    uint64_t virt = proc->mmap_next_addr;
    for (uint64_t i = 0; i < num_pages; i++) {
        uint64_t page_phys = phys + i * PAGE_SIZE;
        uint64_t page_virt = virt + i * PAGE_SIZE;
        uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(page_phys);
        for (uint64_t j = 0; j < PAGE_SIZE; j++) dst[j] = 0;
        if (vmm_map_page_in(proc->cr3, page_virt, page_phys,
                            PTE_USER | PTE_WRITABLE | PTE_NX) != 0) {
            for (uint64_t k = 0; k < num_pages; k++)
                pmm_free_page(phys + k * PAGE_SIZE);
            return -ENOMEM;
        }
    }

    proc->mmap_table[slot].virt_addr = virt;
    proc->mmap_table[slot].phys_addr = phys;
    proc->mmap_table[slot].num_pages = (uint32_t)num_pages;
    proc->mmap_table[slot].used = 1;
    proc->mmap_table[slot].shm_id = -1;
    proc->mmap_table[slot].demand = 0;
    proc->mmap_table[slot].vfs_node = -1;
    proc->mmap_table[slot].file_offset = 0;
    /* Skip 1 guard page after the usable region */
    proc->mmap_next_addr = virt + (num_pages + 1) * PAGE_SIZE;
    proc->used_mem_pages += num_pages;

    return (int64_t)virt;
}

/* --- Page fault handler --- */

int page_fault_handler(uint64_t fault_addr, uint64_t err_code,
                       interrupt_frame_t *frame) {
    thread_t *t = thread_get_current();
    if (!t || !t->process) return -1;  /* Kernel fault */

    process_t *proc = t->process;

    int present = err_code & 1;
    int write   = err_code & 2;
    int user    = err_code & 4;

    if (!user) return -1;  /* Kernel-mode fault */

    if (present && write) {
        /* Page present but not writable — check COW */
        uint64_t *pte = vmm_get_pte(proc->cr3, fault_addr);
        if (pte && (*pte & PTE_COW)) {
            if (!(*pte & PTE_WAS_WRITABLE))
                goto kill;

            uint64_t old_phys = *pte & PTE_ADDR_MASK;
            uint64_t old_flags = *pte & ~PTE_ADDR_MASK;
            uint64_t clean_flags = old_flags & ~(PTE_COW | PTE_WAS_WRITABLE);

            if (pmm_ref_get(old_phys) == 1) {
                *pte = old_phys | PTE_MAKE_WRITABLE(clean_flags) | PTE_PRESENT;
                invlpg_addr(fault_addr & ~0xFFFULL);
                return 0;
            }

            uint64_t new_phys = pmm_alloc_page();
            if (new_phys == 0) goto kill;

            uint8_t *src = (uint8_t *)PHYS_TO_VIRT(old_phys);
            uint8_t *dst = (uint8_t *)PHYS_TO_VIRT(new_phys);
            for (int i = 0; i < 4096; i++) dst[i] = src[i];

            *pte = new_phys | PTE_MAKE_WRITABLE(clean_flags) | PTE_PRESENT;
            invlpg_addr(fault_addr & ~0xFFFULL);

            pmm_ref_dec(old_phys);
            return 0;
        }
    }

    /* Demand paging / swap-in: page not present in user mode */
    if (!present && user) {
        uint64_t *pte = vmm_get_pte(proc->cr3, fault_addr);
        if (pte && swap_is_entry(*pte)) {
            if (swap_in(proc->cr3, fault_addr) == 0) {
                invlpg_addr(fault_addr & ~0xFFFULL);
                return 0;
            }
        }

        uint64_t page_addr = fault_addr & ~0xFFFULL;
        for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
            mmap_entry_t *me = &proc->mmap_table[i];
            if (!me->used || !me->demand) continue;
            uint64_t region_start = me->virt_addr;
            uint64_t region_end = region_start + (uint64_t)me->num_pages * 4096;
            if (page_addr >= region_start && page_addr < region_end) {
                if (me->vfs_node >= 0) {
                    uint64_t new_phys = pmm_alloc_page();
                    if (new_phys == 0) goto kill;
                    uint8_t *fdst = (uint8_t *)PHYS_TO_VIRT(new_phys);

                    uint64_t page_offset_in_region = page_addr - region_start;
                    uint64_t file_off = me->file_offset + page_offset_in_region;
                    int64_t got = vfs_read(me->vfs_node, file_off, fdst, 4096);
                    if (got < 0) got = 0;
                    for (int64_t j = got; j < 4096; j++)
                        fdst[j] = 0;

                    if (vmm_map_page_in(proc->cr3, page_addr, new_phys,
                                        PTE_USER | PTE_NX) == 0) {
                        invlpg_addr(page_addr);
                        return 0;
                    }
                    pmm_free_page(new_phys);
                } else if (demand_page_fault(proc->cr3, page_addr) == 0) {
                    invlpg_addr(page_addr);
                    return 0;
                }
            }
        }
    }

kill:
    {
        uint64_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        uint64_t guard_start = stack_bottom - PAGE_SIZE;
        if (fault_addr >= guard_start && fault_addr < stack_bottom) {
            serial_printf("[fault] Stack overflow detected (pid %lu, addr=%lx, rip=%lx)\n",
                proc->pid, fault_addr, FRAME_PC(frame));
        } else {
            int in_guard_gap = 0;
            for (int i = 0; i < MMAP_MAX_ENTRIES; i++) {
                mmap_entry_t *me = &proc->mmap_table[i];
                if (!me->used) continue;
                uint64_t region_end = me->virt_addr + (uint64_t)me->num_pages * PAGE_SIZE;
                uint64_t gap_end = region_end + PAGE_SIZE;
                if (fault_addr >= region_end && fault_addr < gap_end) {
                    serial_printf("[fault] Guard page hit (pid %lu, addr=%lx past mmap %lx+%u, rip=%lx)\n",
                        proc->pid, fault_addr, me->virt_addr, me->num_pages, FRAME_PC(frame));
                    in_guard_gap = 1;
                    break;
                }
            }
            if (!in_guard_gap)
                serial_printf("[fault] Process %lu killed: fault at %lx (err=%lx, rip=%lx)\n",
                    proc->pid, fault_addr, err_code, FRAME_PC(frame));
        }
    }
    process_terminate(t, -11);
    return 0;
}
