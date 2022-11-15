#include <string.h>
#include "disector.h"

#define TO_UPPER(c) ((c) >= 'a' ? (c) - ('a' - 'A') : (c))

static char *search[] = { "+OK", "USER ", "PASS ", "+OK" };

extern void
disector_parser_reset(struct disector_parser *p) {
    p->state = disector_user;
    p->i     = p->user_carry ? 1 : 0;
    p->user_carry = false;
}

extern void
disector_parser_init(struct disector_parser *p) {
    p->state = disector_wait_pop;
    p->i     = 0;
    p->user_carry = false;
    memset(&p->disector, 0, sizeof(p->disector));
}

static int 
remaining_is_done(struct disector_parser *p, uint8_t search_index) {
    return p->i >= strlen(search[search_index]) - 1; // descontamos el 0 final
}

// espera el greeting POP3 del origin server
static enum disector_state
wait_pop(const uint8_t c, struct disector_parser *p) { // server response es case sensitive
    if (c == search[0][p->i])
        p->i++;
    else
        return disector_incompatible; // no sniffearemos mas esta conexion
    
    return remaining_is_done(p, 0) ? disector_user : disector_wait_pop;
}

// intenta matchear la keyword USER
static enum disector_state
user(const uint8_t c, struct disector_parser *p) {  // client request es case insensitive
    if (TO_UPPER(c) == search[1][p->i])
        p->i++;
    else
        return disector_restart;
    
    return remaining_is_done(p, 1) ? disector_user_copy : disector_user;
}

// guarda el argumento de la keyword USER
static enum disector_state
user_copy(const uint8_t c, struct disector_parser *p) {
    if (c == '\n') {
        p->disector.user[p->i - 1] = 0; // reemplazamos el \r por 0 para imprimirlo luego
        return disector_password;
    }
    p->disector.user[p->i++] = c;
    return disector_user_copy;
}

// intenta matchear la keyword PASS
static enum disector_state
password(const uint8_t c, struct disector_parser *p) {
    if (TO_UPPER(c) == search[2][p->i]) {
        p->i++;
    } else {
        if (TO_UPPER(c) == search[1][0])
            p->user_carry = true;  // esta letra matchea para la keyword USER, asi que la marcamos como valida para la siguiente iteracion
        return disector_restart;
    }
    
    return remaining_is_done(p, 2) ? disector_password_copy : disector_password;
}

// copia el argumento de la keyword PASS
static enum disector_state
password_copy(const uint8_t c, struct disector_parser *p) {
    if (c == '\n') {
        p->disector.pass[p->i - 1] = 0;
        return disector_response;
    }
    p->disector.pass[p->i++] = c;
    return disector_password_copy;
}

// intenta matchear una respuesta positiva al USER/PASS por parte del origin
static enum disector_state
response(const uint8_t c, struct disector_parser *p) {
    if (c == search[3][p->i])
        p->i++;
    else
        return disector_restart;
    
    return remaining_is_done(p, 3) ? disector_done : disector_response;
}

/** entrega un byte al parser, y retorna el nuevo estado del mismo */
static enum disector_state 
disector_parser_feed(struct disector_parser *p, const uint8_t c) {
    enum disector_state next = p->state;

    switch(p->state) {
        case disector_wait_pop:
            next = wait_pop(c, p);
            break;
        case disector_user:
            next = user(c, p);
            break;
        case disector_user_copy:
            next = user_copy(c, p);
            break;
        case disector_password:
            next = password(c, p);
            break;
        case disector_password_copy:
            next = password_copy(c, p);
            break;
        case disector_response:
            next = response(c, p);
            break;
        case disector_done:
        case disector_restart:
            // mantenemos el estado
            break;
        default:
            next = disector_restart;
            break;
    }

    if (next != p->state)
        p->i = 0; // preparamos para el cambio de estado

    return p->state = next;
}

extern enum disector_state
disector_consume(struct disector_parser *p, uint8_t *ptr, size_t n) {
    enum disector_state st = p->state;

    for (size_t i = 0; i < n; i++) {
        const uint8_t c = ptr[i];
        st = disector_parser_feed(p, c);
        if (st == disector_restart)
            disector_parser_reset(p); // resetea y sigue sniffeando todo el contenido que manda el cliente, para no saltearse nada sin querer
        else if (st == disector_incompatible)
            break;
    }
    return st;
}
