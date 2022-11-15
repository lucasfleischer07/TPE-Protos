#include <stdio.h>
#include <stdlib.h>

#include "hello.h"

extern void
hello_parser_init(struct hello_parser *p) {
    p->state     = hello_version;
    p->remaining = 0;
}

extern enum hello_state
hello_parser_feed(struct hello_parser *p, const uint8_t b) {
    switch (p->state) {
    case hello_version:
        if(0x05 == b) {
            p->state = hello_nmethods;
        } else {
            p->state = hello_error_unsupported_version;
        }
        break;

    case hello_nmethods:
        p->remaining = b;
        p->state     = hello_methods;

        if(p->remaining <= 0) {
            p->state = hello_done;
        }

        break;

    case hello_methods:
        if(NULL != p->on_authentication_method) {   // Aca se usa la funcion que pasamos en socks5.c como puntero para ver si es una funcion que acepta el server
            p->on_authentication_method(p, b);
        }
        p->remaining--;
        if(p->remaining <= 0) {
            p->state = hello_done;
        }
        break;
    case hello_done:
    case hello_error_unsupported_version:
        // nada que hacer, nos quedamos en este estado
        break;
    default:
        fprintf(stderr, "unknown state %d\n", p->state);
        abort();
    }

    return p->state;
}

extern bool
hello_is_done(const enum hello_state state, bool *errored) {
    bool ret;
    switch (state) {
    case hello_error_unsupported_version:
        if(0 != errored) {
            *errored = true;
        }
        /* No break*/
    case hello_done:
        ret = true;
        break;
    default:
        ret = false;
        break;
    }
    return ret;
}

extern const char *
hello_error(const struct hello_parser *p) {
    char *ret;
    switch (p->state)   {
    case hello_error_unsupported_version:
        ret = "unsupported version";
        break;
    default:
        ret = "";
        break;
    }
    return ret;
}

extern void
hello_parser_close(struct hello_parser *p) {
    /* no hay nada que liberar */
}

extern enum hello_state
hello_consume(buffer *b, struct hello_parser *p, bool *errored) {
    enum hello_state st = p->state;

    while (buffer_can_read(b))  {
        const uint8_t c = buffer_read(b);
        st = hello_parser_feed(p, c);
        if  (hello_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern int
hello_marshall(buffer *b, const uint8_t method) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 2) {
        return -1;
    }
    buff[0] = 0x05;
    buff[1] = method;
    buffer_write_adv(b, 2);
    return 2;
}
