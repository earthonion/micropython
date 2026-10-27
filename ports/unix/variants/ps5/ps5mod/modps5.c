// modps5 — `import ps5`: console-specific helpers for the PS5 micropython build.
//
//   ps5.escalate()              jailbreak creds: authid + caps + setuid(0)
//   ps5.kread(addr, len)        kernel memory -> bytes
//   ps5.kwrite(addr, data)      kernel memory <- bytes-like
//   ps5.kbase()                 kernel .text base (post-KASLR)
//   ps5.kslide()                KASLR slide vs 0xffffffff80210000
//   ps5.notify(msg)             system notification popup
//   ps5.toast(title, body)      interactive toast (libSceNotification)
//   ps5.klog(msg)               write to the kernel log
//   ps5.find_pid(name)          pid by process name, -1 if absent
//   ps5.pread(pid, addr, len)   other-process memory -> bytes (ptrace)
//   ps5.pwrite(pid, addr, data) other-process memory <- bytes-like
//   ps5.syscall(nr, *args)      arbitrary syscall, up to 6 args
//
// Logic adapted from emoji_verify/util.c.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#include "py/runtime.h"
#include "py/mperrno.h"

// libkernel / libSceNotification exports (no public headers in the SDK)
extern int sceKernelSendNotificationRequest(int, void *, size_t, int);
extern int sceNotificationSend(int userId, bool isLogged, const char *payload);
#define SCE_NOTIFICATION_LOCAL_USER_ID_SYSTEM 0xFE

// ---------------------------------------------------------------------------
// privilege escalation (emoji_verify util.c:escalate)
// ---------------------------------------------------------------------------

static mp_obj_t ps5_escalate(void) {
    pid_t pid = getpid();
    if (kernel_set_ucred_authid(pid, 0x4800000000000010ULL)) {
        mp_raise_OSError(MP_EIO);
    }
    uint8_t caps[16];
    if (kernel_get_ucred_caps(pid, caps)) {
        mp_raise_OSError(MP_EIO);
    }
    caps[7] |= 0x40;
    if (kernel_set_ucred_caps(pid, caps)) {
        mp_raise_OSError(MP_EIO);
    }
    if (setuid(0)) {
        mp_raise_OSError(MP_EPERM);
    }
    return mp_const_true;
}
static MP_DEFINE_CONST_FUN_OBJ_0(ps5_escalate_obj, ps5_escalate);

// ---------------------------------------------------------------------------
// kernel memory
// ---------------------------------------------------------------------------

static mp_obj_t ps5_kread(mp_obj_t addr_obj, mp_obj_t len_obj) {
    mp_uint_t addr = (mp_uint_t)mp_obj_get_int_truncated(addr_obj);
    size_t len = (size_t)mp_obj_get_int(len_obj);
    if (len == 0 || len > (16 << 20)) {
        mp_raise_ValueError(MP_ERROR_TEXT("len out of range"));
    }
    uint8_t *buf = m_new(uint8_t, len);
    if (kernel_copyout((intptr_t)addr, buf, len)) {
        m_del(uint8_t, buf, len);
        mp_raise_OSError(MP_EFAULT);
    }
    mp_obj_t ret = mp_obj_new_bytes(buf, len);
    m_del(uint8_t, buf, len);
    return ret;
}
static MP_DEFINE_CONST_FUN_OBJ_2(ps5_kread_obj, ps5_kread);

static mp_obj_t ps5_kwrite(mp_obj_t addr_obj, mp_obj_t data_obj) {
    mp_uint_t addr = (mp_uint_t)mp_obj_get_int_truncated(addr_obj);
    mp_buffer_info_t buf;
    mp_get_buffer_raise(data_obj, &buf, MP_BUFFER_READ);
    if (kernel_copyin(buf.buf, (intptr_t)addr, buf.len)) {
        mp_raise_OSError(MP_EFAULT);
    }
    return mp_obj_new_int_from_uint(buf.len);
}
static MP_DEFINE_CONST_FUN_OBJ_2(ps5_kwrite_obj, ps5_kwrite);

static mp_obj_t ps5_kbase(void) {
    return mp_obj_new_int_from_uint((mp_uint_t)KERNEL_ADDRESS_TEXT_BASE);
}
static MP_DEFINE_CONST_FUN_OBJ_0(ps5_kbase_obj, ps5_kbase);

static mp_obj_t ps5_kslide(void) {
    return mp_obj_new_int_from_uint((mp_uint_t)KERNEL_ADDRESS_TEXT_BASE - 0xffffffff80210000ULL);
}
static MP_DEFINE_CONST_FUN_OBJ_0(ps5_kslide_obj, ps5_kslide);

// ---------------------------------------------------------------------------
// UI / logging
// ---------------------------------------------------------------------------

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

static mp_obj_t ps5_notify(mp_obj_t msg_obj) {
    const char *msg = mp_obj_str_get_str(msg_obj);
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, msg, sizeof(req.message) - 1);
    return MP_OBJ_NEW_SMALL_INT(sceKernelSendNotificationRequest(0, &req, sizeof(req), 0));
}
static MP_DEFINE_CONST_FUN_OBJ_1(ps5_notify_obj, ps5_notify);

static const char toast_tmpl[] =
    "{\n"
    "  \"rawData\": {\n"
    "    \"viewTemplateType\": \"InteractiveToastTemplateB\",\n"
    "    \"channelType\": \"Downloads\",\n"
    "    \"useCaseId\": \"IDC\",\n"
    "    \"toastOverwriteType\": \"No\",\n"
    "    \"isImmediate\": true,\n"
    "    \"priority\": 100,\n"
    "    \"viewData\": {\n"
    "      \"icon\": {\"type\": \"Url\", \"parameters\": {\"url\": \"\"}},\n"
    "      \"message\": {\"body\": \"%s\"},\n"
    "      \"subMessage\": {\"body\": \"%s\"}\n"
    "    }\n"
    "  },\n"
    "  \"localNotificationId\": \"588193127\"\n"
    "}";

static mp_obj_t ps5_toast(mp_obj_t title_obj, mp_obj_t body_obj) {
    const char *title = mp_obj_str_get_str(title_obj);
    const char *body = mp_obj_str_get_str(body_obj);
    size_t buf_sz = strlen(title) + strlen(body) + sizeof(toast_tmpl) + 1;
    char *buf = m_new(char, buf_sz);
    snprintf(buf, buf_sz, toast_tmpl, body, title);
    int rc = sceNotificationSend(SCE_NOTIFICATION_LOCAL_USER_ID_SYSTEM, true, buf);
    m_del(char, buf, buf_sz);
    return MP_OBJ_NEW_SMALL_INT(rc);
}
static MP_DEFINE_CONST_FUN_OBJ_2(ps5_toast_obj, ps5_toast);

static mp_obj_t ps5_klog(mp_obj_t msg_obj) {
    return MP_OBJ_NEW_SMALL_INT(klog_puts(mp_obj_str_get_str(msg_obj)));
}
static MP_DEFINE_CONST_FUN_OBJ_1(ps5_klog_obj, ps5_klog);

// ---------------------------------------------------------------------------
// processes (emoji_verify util.c: find_pid / ptrace helpers)
// ---------------------------------------------------------------------------

static mp_obj_t ps5_find_pid(mp_obj_t name_obj) {
    const char *name = mp_obj_str_get_str(name_obj);
    int mib[4] = {1, 14, 8, 0}; // CTL_KERN, KERN_PROC, KERN_PROC_PROC
    size_t sz;
    if (sysctl(mib, 4, 0, &sz, 0, 0)) {
        mp_raise_OSError(MP_EIO);
    }
    uint8_t *buf = malloc(sz);
    if (!buf || sysctl(mib, 4, buf, &sz, 0, 0)) {
        free(buf);
        mp_raise_OSError(MP_EIO);
    }
    pid_t pid = -1;
    pid_t me = getpid();
    for (uint8_t *p = buf; p < buf + sz;) {
        int rs = *(int *)p;
        pid_t p2 = *(pid_t *)(p + 72);
        const char *n = (const char *)(p + 447);
        if (rs <= 0) {
            break;
        }
        if (!strcmp(name, n) && p2 != me) {
            pid = p2;
        }
        p += rs;
    }
    free(buf);
    return MP_OBJ_NEW_SMALL_INT(pid);
}
static MP_DEFINE_CONST_FUN_OBJ_1(ps5_find_pid_obj, ps5_find_pid);

// ptrace with temporarily swapped-in privileged creds (util.c:do_ptrace)
static int do_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    uint8_t privcaps[16];
    memset(privcaps, 0xff, sizeof(privcaps));
    pid_t me = getpid();
    uint8_t caps[16];
    uint64_t authid = kernel_get_ucred_authid(me);
    if (kernel_get_ucred_caps(me, caps)) {
        return -1;
    }
    kernel_set_ucred_authid(me, 0x4800000000010003ULL);
    kernel_set_ucred_caps(me, privcaps);
    int ret = (int)__syscall(SYS_ptrace, request, pid, addr, data);
    kernel_set_ucred_authid(me, authid);
    kernel_set_ucred_caps(me, caps);
    return ret;
}

static mp_obj_t ps5_pread(mp_obj_t pid_obj, mp_obj_t addr_obj, mp_obj_t len_obj) {
    pid_t pid = (pid_t)mp_obj_get_int(pid_obj);
    mp_uint_t addr = (mp_uint_t)mp_obj_get_int_truncated(addr_obj);
    size_t len = (size_t)mp_obj_get_int(len_obj);
    if (len == 0 || len > (16 << 20)) {
        mp_raise_ValueError(MP_ERROR_TEXT("len out of range"));
    }
    uint8_t *buf = m_new(uint8_t, len);
    struct ptrace_io_desc iod = {PIOD_READ_D, (void *)addr, buf, len};
    if (do_ptrace(PT_IO, pid, (caddr_t)&iod, 0)) {
        m_del(uint8_t, buf, len);
        mp_raise_OSError(MP_EFAULT);
    }
    mp_obj_t ret = mp_obj_new_bytes(buf, len);
    m_del(uint8_t, buf, len);
    return ret;
}
static MP_DEFINE_CONST_FUN_OBJ_3(ps5_pread_obj, ps5_pread);

static mp_obj_t ps5_pwrite(mp_obj_t pid_obj, mp_obj_t addr_obj, mp_obj_t data_obj) {
    pid_t pid = (pid_t)mp_obj_get_int(pid_obj);
    mp_uint_t addr = (mp_uint_t)mp_obj_get_int_truncated(addr_obj);
    mp_buffer_info_t buf;
    mp_get_buffer_raise(data_obj, &buf, MP_BUFFER_READ);
    struct ptrace_io_desc iod = {PIOD_WRITE_D, (void *)addr, buf.buf, buf.len};
    if (do_ptrace(PT_IO, pid, (caddr_t)&iod, 0)) {
        mp_raise_OSError(MP_EFAULT);
    }
    return mp_obj_new_int_from_uint(buf.len);
}
static MP_DEFINE_CONST_FUN_OBJ_3(ps5_pwrite_obj, ps5_pwrite);

// ---------------------------------------------------------------------------
// arbitrary syscall
// ---------------------------------------------------------------------------

static mp_obj_t ps5_syscall(size_t n_args, const mp_obj_t *args) {
    long nr = (long)mp_obj_get_int(args[0]);
    long a[6] = {0, 0, 0, 0, 0, 0};
    for (size_t i = 1; i < n_args && i <= 6; i++) {
        a[i - 1] = (long)mp_obj_get_int_truncated(args[i]);
    }
    long ret = __syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
    return mp_obj_new_int((mp_int_t)ret);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(ps5_syscall_obj, 1, 7, ps5_syscall);

// ---------------------------------------------------------------------------
// module registration
// ---------------------------------------------------------------------------

static const mp_rom_map_elem_t ps5_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ps5) },
    { MP_ROM_QSTR(MP_QSTR_escalate), MP_ROM_PTR(&ps5_escalate_obj) },
    { MP_ROM_QSTR(MP_QSTR_kread),    MP_ROM_PTR(&ps5_kread_obj) },
    { MP_ROM_QSTR(MP_QSTR_kwrite),   MP_ROM_PTR(&ps5_kwrite_obj) },
    { MP_ROM_QSTR(MP_QSTR_kbase),    MP_ROM_PTR(&ps5_kbase_obj) },
    { MP_ROM_QSTR(MP_QSTR_kslide),   MP_ROM_PTR(&ps5_kslide_obj) },
    { MP_ROM_QSTR(MP_QSTR_notify),   MP_ROM_PTR(&ps5_notify_obj) },
    { MP_ROM_QSTR(MP_QSTR_toast),    MP_ROM_PTR(&ps5_toast_obj) },
    { MP_ROM_QSTR(MP_QSTR_klog),     MP_ROM_PTR(&ps5_klog_obj) },
    { MP_ROM_QSTR(MP_QSTR_find_pid), MP_ROM_PTR(&ps5_find_pid_obj) },
    { MP_ROM_QSTR(MP_QSTR_pread),    MP_ROM_PTR(&ps5_pread_obj) },
    { MP_ROM_QSTR(MP_QSTR_pwrite),   MP_ROM_PTR(&ps5_pwrite_obj) },
    { MP_ROM_QSTR(MP_QSTR_syscall),  MP_ROM_PTR(&ps5_syscall_obj) },
};
static MP_DEFINE_CONST_DICT(ps5_module_globals, ps5_module_globals_table);

const mp_obj_module_t ps5_user_cmodule = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&ps5_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_ps5, ps5_user_cmodule);
