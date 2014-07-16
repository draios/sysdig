flags {
    file = {
        [0] = "O_NONE",
        "O_RDONLY",
        "O_WRONLY",
       -- "O_RDWR" (PPM_O_RDONLY | PPM_O_WRONLY)
        "O_CREAT",
        "O_APPEND",
        "O_DSYNC",
        "O_EXCL",
        "O_NONBLOCK",
        "O_SYNC",
        "O_TRUNC",
        "O_DIRECT",
        "O_DIRECTORY",
        "O_LARGEFILE"
    },
    clone = {
        "CLONE_FILES",
        "CLONE_FS",
        "CLONE_IO",
        "CLONE_NEWIPC",
        "CLONE_NEWNET",
        "CLONE_NEWNS",
        "CLONE_NEWPID",
        "CLONE_NEWUTS",
        "CLONE_PARENT",
        "CLONE_PARENT_SETTID",
        "CLONE_PTRACE",
        "CLONE_SIGHAND",
        "CLONE_SYSVSEM",
        "CLONE_THREAD",
        "CLONE_UNTRACED",
        "CLONE_VM",
        "CLONE_INVERTED", -- libsinsp-specific flag. It's set if clone() returned
                          -- in the child process before than in the parent process
        "CL_NAME_CHANGED", -- libsinsp-specific flag. Set when the thread name
                           -- changes (for example because execve was called)
        "CL_CLOSED"       -- thread has been closed
    },
    poll = {
        "POLLIN",
        "POLLPRI",
        "POLLOUT",
        "POLLRDHUP",
        "POLLERR",
        "POLLHUP",
        "POLLNVAL",
        "POLLRDNORM",
        "POLLRDBAND",
        "POLLWRNORM",
        "POLLWRBAND"
    },
    prot = {
        [0] = "PROT_NONE",
        "PROT_READ",
        "PROT_WRITE",
        "PROT_EXEC",
        "PROT_SEM",
        "PROT_GROWSDOWN",
        "PROT_GROWSUP",
        "PROT_SAO"
    },
    mmap = {
        "MAP_SHARED",
        "MAP_PRIVATE",
        "MAP_FIXED",
        "MAP_ANONYMOUS",
        "MAP_32BIT",
        "MAP_RENAME",
        "MAP_NORESERVE",
        "MAP_POPULATE",
        "MAP_NONBLOCK",
        "MAP_GROWSDOWN",
        "MAP_DENYWRITE",
        "MAP_EXECUTABLE",
        "MAP_INHERIT",
        "MAP_FILE",
        "MAP_LOCKED"
    },
    splice = {
        "SPLICE_F_MOVE",
        "SPLICE_F_NONBLOCK",
        "SPLICE_F_MORE",
        "SPLICE_F_GIFT"
    }
}

