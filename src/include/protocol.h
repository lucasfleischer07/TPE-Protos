#ifndef protocol_H
#define protocol_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

//Tamaño de username y password segun la RFC 1929, deben tener un tamaño entre 1 y 255 bytes
#define USERNAME_SIZE 256
#define PASSWORD_SIZE 256

#define IS_ALNUM(x) (x>='a' && (x) <= 'z') || (x>='A' && x <= 'Z') || (x>='0' && x <= '9')


/** Archivo encargado del manejo del protocolo, parseos y funciones*/
/**
 * Request 

   VER | USER_TOKEN | MÉTODO | DLEN | DATA
    1       16        1       2      1 to 8191

    VER : Tiene el valor de la version del protocolo, debe ser --> X' 01'

    USERNAME : Forma de autenticacion, 16 caracteres que identifican al usuario

    Metodo : Accion a realizar puede ser    ---->     X' 00'  cantidad de conexiones históricas
                                                      X' 01'  cantidad de conexiones concurrentes
                                                      X' 02'  cantidad de bytes transferidos 
                                                      X' 03'  switch password disector POP3
                                                      X' 04'  agregar usuario del proxy
                                                      X' 05'  borrar usuarios del proxy
                                                      X' 06'  agregar usuario admin
                                                      X' 07'  borrar usuarios admin
                                                      X' 08'  listado de usuarios del proxy


    DLEN : Cantidad de bytes del segmento de DATA, para los metodos: X' 00',X' 01',X' 02',X' 08'
           debe no tenerse en consideracion la DATA

    DATA : Campo con informacion extra que pueda requerirse para ejecutar algun metodo.
*/  

#define TOKEN_SIZE 16
#define DLEN_SIZE 0x2

enum protocol_state {            
    protocol_version,
    protocol_token,
    protocol_method,
    protocol_dlen,
    protocol_data,

    // apartir de aca estan done
    protocol_done,

    // y apartir de aca son considerado con error 
    protocol_error,
    protocol_error_unsupported_version,
    protocol_error_invalid_token,
    protocol_error_unsupported_method,
    protocol_error_invalid_data,
};

enum protocol_response_status {
    protocol_status_succeeded                            = 0x00,
    protocol_status_invalid_version                      = 0x01,
    protocol_status_invalid_method                       = 0x02,
    protocol_status_invalid_data                         = 0x03,
    protocol_status_error_auth                           = 0x04,
    protocol_status_server_error                         = 0x05,

};

enum protocol_method {
    get_historic                = 0x00,
    get_concurrent              = 0x01,
    get_transfered              = 0x02,
    pop3disector                = 0x03,
    add_proxyuser               = 0x04,
    delete_proxyuser            = 0x05,
    add_admin                   = 0x06,
    delete_admin                = 0x07,
    get_proxyusers              = 0x08,
};


enum disector_data {
    disector_off    = 0x00,
    disector_on     = 0x01,
};

struct add_proxy_user {
    char        user[USERNAME_SIZE];
    char        pass[PASSWORD_SIZE]; 
};

struct add_admin_user {
    char        user[USERNAME_SIZE];
    char        token[TOKEN_SIZE];
};

//Solo Switch Disector y la creacion o destruccion de usuarios recibe DATA
//Tiene los posibles campos que puede recivir, no deben llenarse todos 
union data {
    char                            user[USERNAME_SIZE]; // EL usuario a borrar
    enum   disector_data     disector_data_params;
    struct add_proxy_user    add_proxy_user_param;
    struct add_admin_user    add_admin_user_param;
};

union data_len {
        uint16_t len;
        uint8_t byte[2];
};

struct protocol {
    char                    token[TOKEN_SIZE];
    enum  protocol_method    method;
    uint16_t                dlen;
    union data              data;
};

struct protocol_parser {
    struct protocol *protocol;
    enum protocol_state state;
    /** cuantos bytes tenemos que leer*/
    uint16_t len;
    /** cuantos bytes ya leimos */
    uint16_t i;
    int separated;
};

/** inicializa el parser del protocolo */
void protocol_parser_init(struct protocol_parser *p);

/** consume el buffer read de la coneccion y lo procesa */
extern enum protocol_state protocol_consume(buffer *b, struct protocol_parser *p);

/** Funcion que devuelve verdadero cuando se finaliza el parseo  */
bool protocol_is_done(enum protocol_state state);



#endif