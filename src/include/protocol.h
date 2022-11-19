#ifndef MONITOR_H
#define MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

/** Archivo encargado del manejo del protocolo, parseos y funciones*/
/**
 * Request 

   VER | USERNAME | MÉTODO | DLEN | DATA
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

enum monitor_state {            
    monitor_version,
    monitor_token,
    monitor_method,
    monitor_dlen,
    monitor_data,

    // apartir de aca estan done
    monitor_done,

    // y apartir de aca son considerado con error 
    monitor_error,
    monitor_error_unsupported_version,
    monitor_error_invalid_token,
    monitor_error_unsupported_method,
    monitor_error_invalid_data,
};

enum monitor_response_status {
    monitor_status_succeeded                            = 0x00,
    monitor_status_invalid_version                      = 0x01,
    monitor_status_invalid_method                       = 0x02,
    monitor_status_invalid_data                         = 0x04,
    monitor_status_error_auth                           = 0x05,
    monitor_status_server_error                         = 0x06,

};

enum monitor_method {
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



#endif