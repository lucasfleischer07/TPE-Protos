#ifndef DISECTOR_H
#define DISECTOR_H

#include <stdint.h>
#include "buffer.h"

/** POP3 username/password disector */

enum disector_state {   
    disector_wait_pop,      // espera hasta encontrar un +OK por parte del origin         
    disector_user,          // buscando keyword USER
    disector_user_copy,     // guardando el username
    disector_password,      // buscando keyword PASS
    disector_password_copy, // guardando la password
    disector_response,      // buscando keyword +OK
    disector_done,          // logramos obtener una credencial
    disector_restart,       // lo que veniamos armando no logro matchear credencial, hay que empezar devuelta
    disector_incompatible,  // estado terminal, la comunicacion no es POP3
};

struct disector {
    /** guarda el usuario encontrado */
    char     user[0xFF];
    /** guarda la password encontrada */
    char     pass[0xFF];
    /** intentara formar +OK */
    char     status[3];
};

struct disector_parser {
    struct disector disector;
    enum disector_state state;

    /** posicion actual que estamos leyendo */
    uint8_t i;
    /** para el caso en el que se lea USER <name> y nuevamente USER <name> a continuacion */
    bool user_carry;
};

/** inicializa el parser */
void
disector_parser_init(struct disector_parser *p);

extern void
disector_parser_reset(struct disector_parser *p);

/**
 * por cada elemento del buffer llama a "disector_parser_feed" hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 * Lee hasta n bytes a partir de la direccion ptr dada.
 * 
 * param errored parametro de salida. si es diferente de NULL se deja dicho valor
 * si el parsing se debio a una condicion de error
 */
enum disector_state
disector_consume(struct disector_parser *p, uint8_t *ptr, size_t n);

void 
disector_close(struct  disector_parser *p);

#endif
