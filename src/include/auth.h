#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include "buffer.h"

/**
 * Once the SOCKS V5 server has started, and the client has selected the
   Username/Password Authentication protocol, the Username/Password
   subnegotiation begins.  This begins with the client producing a
   Username/Password request:

           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+

    The VER field contains the current version of the subnegotiation,
   which is X'01'. The ULEN field contains the length of the UNAME field
   that follows. The UNAME field contains the username as known to the
   source operating system. The PLEN field contains the length of the
   PASSWD field that follows. The PASSWD field contains the password
   association with the given UNAME.

   The server verifies the supplied UNAME and PASSWD, and sends the
   following response:

                        +----+--------+
                        |VER | STATUS |
                        +----+--------+
                        | 1  |   1    |
                        +----+--------+

   A STATUS field of X'00' indicates success. If the server returns a
   `failure' (STATUS value other than X'00') status, it MUST close the
   connection.

    request example: 1 5 12345 5 12345
    response: 1 0
*/

enum auth_state {            
    auth_version,
    auth_ulen,
    auth_uname,
    auth_plen,
    auth_passwd,

    // apartir de aca estan done
    auth_done,

    // y apartir de aca son considerado con error 
    auth_error,
    auth_error_unsupported_version,
    auth_error_invalid,

};

enum auth_response_status {
    auth_status_succeeded                            = 0x00,
    auth_status_failure                              = 0x01,
};

struct auth {
    char     uname[0xFF];
    char     passwd[0xFF];
};

struct auth_parser {
    struct auth *auth;
    enum auth_state state;

    /* cuantos bytes tenemos que leer ya que tenemos campos variables en unamme y passwd */
    uint8_t len;

    /* Cuantos bytes ya leimos */
    uint8_t i;  
};

/** inicializa el parser */
void
auth_parser_init(struct auth_parser *p);

/**
 * por cada elemento del buffer llama a "monitor_parser_feed" hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 * 
 * param errored parametro de salida. si es diferente de NULL se deja dicho valor
 * si el parsing se debio a una condicion de error
 */
enum auth_state
auth_consume(buffer *b, struct auth_parser *p, bool *errored);

/*
 * Permite distinguir a quien usa socks_hello_parser_feed si debe seguir 
 * enviando caracteres o no
 * 
 * En caso de haber terminado permite tambien saber si se debe a un error.
 */
bool 
auth_is_done(const enum  auth_state st, bool *errored);

void 
auth_close(struct  auth_parser *p);

/*
 * serializa en buff una respuesta al request,
 * 
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no habia 
 * espacio suficiente.
 */
extern int 
auth_marshall(buffer *b, const enum  auth_response_status status);

#endif
