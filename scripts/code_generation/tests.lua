-- Minimal syscall definition
test {
    input = [[ events { {
                name = "brk",
                kind = "syscall",
                category = "EC_MEMORY",
                enter_params = {},
                exit_params = {}
            } } ]],
    output = {
        ['event_type.inc'] = [[
            PPME_SYSCALL_BRK_E = 158,
            PPME_SYSCALL_BRK_X = 159,
            PPM_EVENT_MAX = 160
        ]],
        ['event_info.inc'] = [[
            /* PPME_SYSCALL_BRK_E */{ "brk", EC_MEMORY, EF_NONE, 0, { } },
            /* PPME_SYSCALL_BRK_X */{ "brk", EC_MEMORY, EF_NONE, 0, { } },
        ]],
        ['flags.h'] = '',
        ['flags.inc'] = '',
        ['ppm_events.inc'] = '',
        ['syscall_table.inc'] = [[#ifdef __NR_brk
            [__NR_brk - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_BRK_E, PPME_SYSCALL_BRK_X },
        #endif]],
    }
}

-- event_type
test {
    event_type = [[
        PPME_SYSCALL_MMAP_E = 12,
        PPME_SYSCALL_MMAP_X = 13,
        PPM_FIRST_GENERATED_EVENT = 14,
    ]],
    input = [[ events { {
                name = "brk",
                kind = "syscall",
                category = "EC_MEMORY",
                enter_params = {},
                exit_params = {}
            } } ]],
    output = {
        ['event_type.inc'] = [[
            PPME_SYSCALL_BRK_E = 14,
            PPME_SYSCALL_BRK_X = 15,
            PPM_EVENT_MAX = 16
        ]]
    }
}


-- Params
test {
    input = [[ events { {
                name = "brk",
                kind = "syscall",
                category = "EC_MEMORY",
                enter_params = { UINT64("addr", HEX) },
                exit_params = {}
            } } ]],
    output = {
        ['event_info.inc'] = [[
            /* PPME_SYSCALL_BRK_E */{ "brk", EC_MEMORY, EF_NONE, 1, { { "addr", PT_UINT64, PF_HEX } } },
            /* PPME_SYSCALL_BRK_X */{ "brk", EC_MEMORY, EF_NONE, 0, { } },
        ]],
    }
}

test {
    input = [[ events { {
                name = "munmap",
                kind = "syscall",
                category = "EC_MEMORY",
                enter_params = { UINT64("addr", HEX), UINT64("length") },
                exit_params = {}
            } } ]],
    output = {
        ['event_info.inc'] = '^.*{ "munmap", EC_MEMORY, EF_NONE, 2, { { "addr", PT_UINT64, PF_HEX }, { "length", PT_UINT64, PF_DEC } } },'
    }
}

test {
    input = [[ events { {
                name = "munmap",
                kind = "syscall",
                category = "EC_MEMORY",
                enter_params = {},
                exit_params = { ERRNO("res") }
            } } ]],
    output = {
        ['event_info.inc'] = '^.*{ "munmap", EC_MEMORY, EF_NONE, 1, { { "res", PT_ERRNO, PF_DEC } } },'
    }
}

-- Flags
test {
    input = [[ events { {
                name = "splice",
                kind = "syscall",
                category = "EC_IO_OTHER",
                flags = "EF_USES_FD",
                enter_params = {},
                exit_params = {}
            } } ]],
    output = {
        ['event_info.inc'] = '^.*{ "splice", EC_IO_OTHER, EF_USES_FD, 0, { } },'
    }
}

test {
    input = [[ events { {
                name = "open",
                kind = "syscall",
                category = "EC_FILE",
                flags = { "EF_CREATES_FD", "EF_MODIFIES_STATE" },
                enter_params = {},
                exit_params = {}
            } } ]],
    output = {
        ['event_info.inc'] = '^.*%(enum ppm_event_flags%)%(EF_CREATES_FD | EF_MODIFIES_STATE%), 0'
    }
}

-- Fillers
test {
    input = [[ events { {
                name = "mmap",
                kind = "syscall",
                category = "EC_MEMORY",
                enter_params = {},
                exit_params = {},
                fillers = { enter = 'f_sys_mmap_e', exit = 'f_sys_brk_munmap_mmap_x' }
            } } ]],
    output = {
        ['ppm_events.inc'] = [[
            [PPME_SYSCALL_MMAP_E] = {f_sys_mmap_e},
            [PPME_SYSCALL_MMAP_X] = {f_sys_brk_munmap_mmap_x},
        ]]
    }
}

-- Autofill
test {
    input = [[ events { {
                name = "brk",
                kind = "syscall",
                category = "EC_MEMORY",
                enter_params = {},
                exit_params = {},
                fillers = { enter = AUTOFILL(0) }
            } } ]],
    output = {
        ['ppm_events.inc'] = '^.*{PPM_AUTOFILL, 1, APT_REG, { {0} }}'
    }
}

test {
    input = [[ events { {
                name = "creat",
                kind = "syscall",
                category = "EC_FILE",
                enter_params = {},
                exit_params = {},
                fillers = { exit = AUTOFILL(RETVAL, 0, DEFAULT) }
            } } ]],
     output = {
         ['ppm_events.inc'] = '^.*{AF_ID_RETVAL}, {0}, {AF_ID_USEDEFAULT, 0}'
     }
}

test {
    input = [[ events { {
                name = "splice",
                kind = "syscall",
                category = "EC_OTHER",
                enter_params = {},
                exit_params = {},
                fillers = { enter = AUTOFILL(REG, 0, 2, 4, 5), exit = AUTOFILL(RETVAL) }
            } } ]],
    output = {
        ['ppm_events.inc'] = [[
            [PPME_SYSCALL_SPLICE_E] = {PPM_AUTOFILL, 4, APT_REG, { {0}, {2}, {4}, {5} }},
            [PPME_SYSCALL_SPLICE_X] = {PPM_AUTOFILL, 1, APT_REG, { {AF_ID_RETVAL} }},
        ]]
    }
}

-- kind = "none"
test {
    input = [[ events { {
                name = "schedswitch_6",
                kind = "none",
                category = "EC_SCHEDULER",
                enter_params = { PID("next") },
                exit_params = {},
                fillers = { enter = 'f_sched_switch_e' }
            } } ]],
    output = {
        ['event_info.inc'] = [[
            /* PPME_SCHEDSWITCH_6_E */{ "schedswitch_6", EC_SCHEDULER, EF_NONE, 1, { { "next", PT_PID, PF_DEC } } },
            /* PPME_SCHEDSWITCH_6_X */{ "schedswitch_6", EC_SCHEDULER, EF_NONE, 0, { } },
        ]],
        ['ppm_events.inc'] = [[
            [PPME_SCHEDSWITCH_6_E] = {f_sched_switch_e},
        ]]
    }
}

-- Socket call
test {
    input = [[ events { {
                name = "listen",
                kind = "socketcall",
                category = "EC_NET",
                enter_params = {},
                exit_params = {},
                fillers = { enter = AUTOFILL(SOCK, 0, 1) }
            } } ]],
    output = {
        ['ppm_events.inc'] = [[
            [PPME_SOCKET_LISTEN_E] = {PPM_AUTOFILL, 2, APT_SOCK, { {0}, {1} }},
        ]]
    }
}

-- Never drop
test {
    input = [[ events { {
                name = "brk",
                kind = "syscall",
                category = "EC_MEMORY",
                never_drop = true,
                enter_params = {},
                exit_params = {}
             } } ]],
     output = {
         ['syscall_table.inc'] = '^.*UF_USED | UF_NEVER_DROP'
     }
}

-- Version
test {
    input = [[ events { {
                name = "brk",
                kind = "syscall",
                category = "EC_MEMORY",
                version = 4,
                enter_params = {},
                exit_params = {}
             } } ]],
    output = {
        ['event_type.inc'] = [[
            PPME_SYSCALL_BRK_4_E = 158,
            PPME_SYSCALL_BRK_4_X = 159,
            PPM_EVENT_MAX = 160
        ]],
        ['event_info.inc'] = [[
            /* PPME_SYSCALL_BRK_4_E */{ "brk", EC_MEMORY, EF_NONE, 0, { } },
            /* PPME_SYSCALL_BRK_4_X */{ "brk", EC_MEMORY, EF_NONE, 0, { } },
        ]],
        ['syscall_table.inc'] = [[#ifdef __NR_brk
            [__NR_brk - SYSCALL_TABLE_ID0] = { UF_USED, PPME_SYSCALL_BRK_4_E, PPME_SYSCALL_BRK_4_X },
        #endif]],
    }
}

 -- Flags
test {
    input = [[ flags {
         splice = {
             "SPLICE_F_MOVE",
             "SPLICE_F_NONBLOCK",
             "SPLICE_F_MORE",
             "SPLICE_F_GIFT"
         } } ]],
    output = {
        ['flags.h'] = [[
            /* splice_flags*/
            #define PPM_SPLICE_F_MOVE (1 << 0)
            #define PPM_SPLICE_F_NONBLOCK (1 << 1)
            #define PPM_SPLICE_F_MORE (1 << 2)
            #define PPM_SPLICE_F_GIFT (1 << 3)
            extern const struct ppm_name_value splice_flags[];
        ]],
        ['flags.inc'] = [[
            const struct ppm_name_value splice_flags[] = {
                { "SPLICE_F_MOVE", PPM_SPLICE_F_MOVE },
                { "SPLICE_F_NONBLOCK", PPM_SPLICE_F_NONBLOCK },
                { "SPLICE_F_MORE", PPM_SPLICE_F_MORE },
                { "SPLICE_F_GIFT", PPM_SPLICE_F_GIFT },
                { }
            };
        ]]
    }
}

test {
    input = [[ flags {
         prot = {
             [0] = "PROT_NONE",
             "PROT_READ",
             "PROT_WRITE"
         } } ]],
    output = {
        ['flags.h'] = [[
            /* prot_flags*/
            #define PPM_PROT_NONE 0
            #define PPM_PROT_READ (1 << 0)
            #define PPM_PROT_WRITE (1 << 1)
            extern const struct ppm_name_value prot_flags[];
        ]],
        ['flags.inc'] = [[
            const struct ppm_name_value prot_flags[] = {
                { "PROT_NONE", PPM_PROT_NONE },
                { "PROT_READ", PPM_PROT_READ },
                { "PROT_WRITE", PPM_PROT_WRITE },
                { }
            };
        ]]
    }
}

