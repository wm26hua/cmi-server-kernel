#!/usr/bin/env python3
"""Apply KernelSU-Next legacy manual hooks to LineageOS 4.19 sm8250 kernel."""


def patch_file(path, replacements):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    for desc, target, new in replacements:
        assert target in text, f"[{path}] Anchor not found for: {desc}"
        assert text.count(target) == 1, f"[{path}] Ambiguous anchor for: {desc}"
        text = text.replace(target, new, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"[OK] Patched {path}")


def main():
    patch_file(
        "kernel/reboot.c",
        [
            (
                "extern ksu_handle_sys_reboot",
                "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n"
                "#endif\n\n"
                "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,",
            ),
            (
                "call ksu_handle_sys_reboot",
                "\t/* We only trust the superuser with rebooting the system. */\n"
                "\tif (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
                "#endif\n"
                "\t/* We only trust the superuser with rebooting the system. */\n"
                "\tif (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))",
            ),
        ],
    )

    patch_file(
        "fs/exec.c",
        [
            (
                "extern ksu_handle_execveat",
                "static int __do_execve_file(int fd, struct filename *filename,",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);\n"
                "#endif\n\n"
                "static int __do_execve_file(int fd, struct filename *filename,",
            ),
            (
                "call ksu_handle_execveat",
                "\tif (IS_ERR(filename))\n\t\treturn PTR_ERR(filename);",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
                "#endif\n"
                "\tif (IS_ERR(filename))\n\t\treturn PTR_ERR(filename);",
            ),
        ],
    )

    patch_file(
        "fs/open.c",
        [
            (
                "extern ksu_handle_faccessat",
                "long do_faccessat(int dfd, const char __user *filename, int mode)",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);\n"
                "#endif\n\n"
                "long do_faccessat(int dfd, const char __user *filename, int mode)",
            ),
            (
                "call ksu_handle_faccessat",
                "\tif (mode & ~S_IRWXO)",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
                "#endif\n"
                "\tif (mode & ~S_IRWXO)",
            ),
        ],
    )

    patch_file(
        "fs/stat.c",
        [
            (
                "extern ksu_handle_stat",
                "int vfs_statx(int dfd, const char __user *filename, int flags,",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);\n"
                "#endif\n\n"
                "int vfs_statx(int dfd, const char __user *filename, int flags,",
            ),
            (
                "call ksu_handle_stat",
                "\tif ((flags & ~(AT_SYMLINK_NOFOLLOW",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_stat(&dfd, &filename, &flags);\n"
                "#endif\n"
                "\tif ((flags & ~(AT_SYMLINK_NOFOLLOW",
            ),
            (
                "extern ksu_handle_newfstat_ret",
                "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);\n"
                "#endif\n\n"
                "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)",
            ),
            (
                "call ksu_handle_newfstat_ret",
                "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n\n\treturn error;",
                "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n"
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tif (!error)\n\t\tksu_handle_newfstat_ret(&fd, &statbuf);\n"
                "#endif\n\n"
                "\treturn error;",
            ),
        ],
    )

    patch_file(
        "fs/read_write.c",
        [
            (
                "extern and call ksu_handle_sys_read",
                "ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)\n"
                "{\n"
                "\tstruct fd f = fdget_pos(fd);\n"
                "\tssize_t ret = -EBADF;\n"
                "\n"
                "\tif (f.file) {",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "extern void ksu_handle_sys_read(unsigned int fd);\n"
                "#endif\n\n"
                "ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)\n"
                "{\n"
                "\tstruct fd f = fdget_pos(fd);\n"
                "\tssize_t ret = -EBADF;\n"
                "\n"
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_sys_read(fd);\n"
                "#endif\n"
                "\tif (f.file) {",
            ),
        ],
    )

    patch_file(
        "drivers/input/input.c",
        [
            (
                "extern and call ksu_handle_input_handle_event",
                "void input_event(struct input_dev *dev,\n"
                "\t\t unsigned int type, unsigned int code, int value)\n"
                "{\n"
                "\tunsigned long flags;\n"
                "\n"
                "\tif (is_event_supported(type, dev->evbit, EV_MAX)) {",
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);\n"
                "#endif\n\n"
                "void input_event(struct input_dev *dev,\n"
                "\t\t unsigned int type, unsigned int code, int value)\n"
                "{\n"
                "\tunsigned long flags;\n"
                "\n"
                "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_input_handle_event(&type, &code, &value);\n"
                "#endif\n"
                "\tif (is_event_supported(type, dev->evbit, EV_MAX)) {",
            ),
        ],
    )


if __name__ == "__main__":
    main()
