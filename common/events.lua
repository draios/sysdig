events {
    {
        name = "brk",
        version = 4,
        kind = "syscall",
        category = "EC_MEMORY",
        enter_params = { UINT64("addr", HEX) },
        exit_params = { UINT64("res", HEX),
                        UINT32("vm_size"), UINT32("vm_rss"), UINT32("vm_swap") },
        fillers = { enter = AUTOFILL(0), exit = "f_sys_brk_munmap_mmap_x" }
    },
    {
        name = "mmap",
        kind = "syscall",
        category = "EC_MEMORY",
        enter_params = { UINT64("addr", HEX), UINT64("length"),
                         FLAGS32("prot", flags.prot), FLAGS32("flags", flags.mmap),
                         FD("fd"), UINT64("offset") },
        exit_params = { ERRNO("res"),
                        UINT32("vm_size"), UINT32("vm_rss"), UINT32("vm_swap") },
        fillers = { enter = "f_sys_mmap_e", exit = "f_sys_brk_munmap_mmap_x" }
    },
    {
        name = "mmap2",
        kind = "syscall",
        category = "EC_MEMORY",
        enter_params = { UINT64("addr", HEX), UINT64("length"),
                         FLAGS32("prot", flags.prot), FLAGS32("flags", flags.mmap),
                         FD("fd"), UINT64("pgoffset") },
        exit_params = { ERRNO("res"),
                        UINT32("vm_size"), UINT32("vm_rss"), UINT32("vm_swap") },
        fillers = { enter = "f_sys_mmap_e", exit = "f_sys_brk_munmap_mmap_x" }
    },
    {
        name = "munmap",
        kind = "syscall",
        category = "EC_MEMORY",
        enter_params = { UINT64("addr", HEX), UINT64("length") },
        exit_params = { ERRNO("res"),
                        UINT32("vm_size"), UINT32("vm_rss"), UINT32("vm_swap") },
        fillers = { enter = AUTOFILL(0, 1), exit = "f_sys_brk_munmap_mmap_x" }
    },
    {
        name = "splice",
        kind = "syscall",
        category = "EC_IO_OTHER",
        flags = "EF_USES_FD",
        enter_params = { FD("fd_in"), FD("fd_out"), UINT64("size"),
                         FLAGS32("flags", flags.splice) },
        exit_params = { ERRNO("res") },
        fillers = { enter = AUTOFILL(0, 2, 4, 5), exit = AUTOFILL(RETVAL) }
    }
}
