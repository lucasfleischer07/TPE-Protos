#include <string.h> //memset

#include "auth.h"

static void
remaining_set(struct auth_parser *p, int len) {
    p->i = 0;
    p->len = len;
}

static int 
remaining_is_done(struct auth_parser *p) {
    return p->i >= p->len;
}

extern void
auth_parser_init(struct auth_parser *p) {
    p->state = auth_version;
    memset(p->auth, 0, sizeof(*(p->auth)));
}

static enum auth_state
version(const uint8_t c, struct auth_parser *p) {
    enum auth_state next;
    switch (c) {
        case 0x01:
            next = auth_ulen;
            break;
        default:
            next = auth_error_unsupported_version;
            break;
    }

    return next;
}

static enum auth_state
ulen(const uint8_t c, struct auth_parser *p) {
    remaining_set(p, c);
    return auth_uname;
}

static enum auth_state
uname(const uint8_t c, struct auth_parser *p) {
    p->auth->uname[p->i++] = c;
    if (remaining_is_done(p))
        return auth_plen;
    return auth_uname;
}

static enum auth_state
plen(const uint8_t c, struct auth_parser *p) {
    remaining_set(p, c);
    return auth_passwd;
}

static enum auth_state
passwd(const uint8_t c, struct auth_parser *p) {
    p->auth->passwd[p->i++] = c;
    if (remaining_is_done(p))
        return auth_done;
    return auth_passwd;
}

/** entrega un byte al parser, retorna true si se llego al final */
static enum auth_state 
auth_parser_feed(struct auth_parser *p, const uint8_t c) {
    enum auth_state next;

    switch(p->state) {
        case auth_version:
            next = version(c, p);
            break;
        case auth_ulen:
            next = ulen(c, p);
            break;
        case auth_uname:
            next = uname(c, p);
            break;
        case auth_plen:
            next = plen(c, p);
            break;
        case auth_passwd:
            next = passwd(c, p);
            break;
        case auth_done:

        case auth_error:
        case auth_error_unsupported_version:
            next = p->state;
            break;
        default:
            next = auth_error;
            break;
    }

    return p->state = next;
}

extern enum auth_state
auth_consume(buffer *b, struct auth_parser *p, bool *errored) {
    enum auth_state st = p->state;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = auth_parser_feed(p, c); // cargamos 1 solo byte
        if (auth_is_done(st, errored))
            break;
    }
    return st;
}

extern bool
auth_is_done(const enum auth_state st, bool *errored) {
    if (st >= auth_error && errored != 0)
        *errored = true;
    return st >= auth_done;
}

// extern lo pone visible para cualquier parte del codigo, para las funciones se pone de forma implicita asi que es redundante
extern void
auth_close(struct auth_parser *p) {
    // nada que hacer
}

extern int
auth_marshall(buffer *b, const enum auth_response_status status) {
    size_t n;
    buffer_write_ptr(b, &n);

    if(n < 2)
        return -1;
    
    buffer_write(b, 0x01); // version
    buffer_write(b, status); // 00 ok, 01 invalid auth

    return 2;
}
