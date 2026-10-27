// PS5 payload runtime shims for the unix port.
//
// Payloads run with stdin/stdout attached to the loader's TCP socket, so
// isatty(0) is false and the stock unix port treats stdin as a script pipe.
// We link with -Wl,--wrap=isatty (the SDK's static libc.a already defines
// isatty, so plain interposition is a duplicate-symbol error) and hijack
// that one call — main.c only calls isatty() at the REPL-or-pipe branch,
// after the VM is fully initialised.
//
// Instead of answering, we start a script server on :9023 and never return:
//
//     echo 'print(6*7)' | nc -q 2 <ps5> 9023    ->    "42"
//
// Each connection: read the script until the client half-closes (nc -q
// semantics), dup2 the client socket onto fds 1+2 so all print/traceback
// output streams back, execute, restore fds, close. Sequential, one script
// at a time. If the listen fails (port busy etc.), we fall back to
// returning "isatty = true" and the normal REPL runs on the 9021 channel.

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "py/builtin.h"
#include "py/compile.h"
#include "py/gc.h"
#include "py/mperrno.h"
#include "py/mphal.h"
#include "py/repl.h"
#include "py/runtime.h"

#define PS5_RUN_PORT 9023
#define PS5_RUN_MAX_SCRIPT (1 << 20)

static void ps5_exec_str(const char *src, size_t len) {
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        qstr source_name = qstr_from_str("<ps5run>");
        mp_lexer_t *lex = mp_lexer_new_from_str_len(source_name, src, len, 0);
        mp_parse_tree_t parse_tree = mp_parse(lex, MP_PARSE_FILE_INPUT);
        mp_obj_t module_fun = mp_compile(&parse_tree, source_name, true);
        mp_call_function_0(module_fun);
        nlr_pop();
    } else {
        // uncaught exception: print traceback (goes to the client via dup2)
        mp_obj_print_exception(&mp_plat_print, (mp_obj_t)nlr.ret_val);
    }
}

static int ps5_serve(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        return -1;
    }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(PS5_RUN_PORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) || listen(srv, 4)) {
        close(srv);
        return -1;
    }
    const char banner[] = "[ps5run] listening on :9023\n";
    (void)!write(1, banner, sizeof(banner) - 1);

    for (;;) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            continue;
        }
        // Read the whole script (client half-closes when done).
        size_t cap = 64 * 1024, len = 0;
        char *buf = malloc(cap);
        if (buf == NULL) {
            close(cli);
            continue;
        }
        for (;;) {
            if (len == cap) {
                if (cap >= PS5_RUN_MAX_SCRIPT) {
                    break;
                }
                cap *= 2;
                char *nb = realloc(buf, cap);
                if (nb == NULL) {
                    break;
                }
                buf = nb;
            }
            ssize_t r = read(cli, buf + len, cap - len);
            if (r > 0) {
                len += r;
            } else {
                break; // 0 = EOF, <0 = error
            }
        }

        // Redirect micropython stdout/stderr to the client socket.
        int save_out = dup(1);
        int save_err = dup(2);
        dup2(cli, 1);
        dup2(cli, 2);
        ps5_exec_str(buf, len);
        if (save_out >= 0) {
            dup2(save_out, 1);
            close(save_out);
        }
        if (save_err >= 0) {
            dup2(save_err, 2);
            close(save_err);
        }

        free(buf);
        shutdown(cli, SHUT_WR); // tell the client the run is over
        close(cli);
    }
    return 0; // unreachable
}

int __wrap_isatty(int fd) {
    if (fd == 0) {
        ps5_serve(); // never returns if the server started
    }
    return fd >= 0;
}

__attribute__((constructor))
static void ps5_boot_probe(void) {
    (void)!write(1, "[ps5boot] ctor\n", 15);
}
