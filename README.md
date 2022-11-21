# CONAN Protocol - SOCKSv5 Proxy

## Introudcción

Este repositorio contiene la implementacion de un proxy server para el protocolo que puede:
 - Atender a múltiples clientes en forma concurrente y simultánea (al menos 500).
 - Soportar autenticación usuario / contraseña [RFC1929](https://datatracker.ietf.org/doc/html/rfc1929).
 - Soportar de mínima conexiones salientes a a servicios TCP a direcciones IPv4, IPV6, o utilizando FQDN que resuelvan cualquiera de estos tipos de direcciones.
 - Ser robusto en cuanto a las opciones de conexión (si se utiliza un FQDN que resuelve a múltiples direcciones IP y una no está disponible debe intentar con otros).
 - Reportar los fallos a los clientes usando toda la potencia del protocolo
 - Implementa mecanismos que permitan recolectar métricas que ayuden a monitorear la operación del sistema.
	 - Cantidad de conexiones históricas
	 - Cantidad de conexiones concurrentes
	 - Cantidad de bytes transferidos
 - Implementa mecanismos que permitan manejar usuarios cambiar la configuración del servidor en tiempo de ejecución sin reiniciar el servidor. 
 - Implementar un registro de acceso que permitan a un administrador entender los accesos de cada uno de los usuarios.
 - Monitorear el tráfico y generar un registro de credenciales de acceso (usuarios y passwords) de forma similar a ettercap por lo menos para protocolo POP3.

## Uso

Primero, se debe descargar el .zip o clonar el repositorio. Una vez realizado esto, nos posicionamos en la carpeta raiz del proyecto ejecutando
```sh
user@user:~$ cd TPE-Protos
```

Una vez realizado esto, para compilar tanto el cliente como el servidor, se debe ejecutar el comando ***make all*** en la raiz .

```sh
user@user:~/TPE-Protos$ make all
```
Luego de ejecutar dicho comando, se crearan los ejecutables:
 - **socks5d:** para el servidor
 - **client5:** para el cliente

Para obtener información de los comandos aceptados por el servidor, se debe ejecutar el servidor junto con el flag: "**-h**". Dicho flag hace que se listen las operaciones permitidas

```sh
user@user:~/TPE-Protos$ ./socks5d -h
Usage: ./socks5d [OPTION]...
   -h              Imprime la ayuda y termina.
   -l<SOCKS addr>  Dirección donde servirá el proxy SOCKS. Por defecto escucha en todas las interfaces.
   -N              Deshabilita los passwords disectors.
   -L<conf  addr>  Dirección donde servirá el servicio de management. Por defecto escucha solo en loopback.
   -p<SOCKS port>  Puerto TCP para conexiones entrantes SOCKS. Por defecto es 1080.
   -P<conf  port>  Puerto TCP para conexiones entrantes del protocolo de configuracion. Por defecto es 8080.
   -u<user>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.
   -v              Imprime información sobre la versión y termina.
   
   --doh-ip    <ip>    
   --doh-port  <port>  XXX
   --doh-host  <host>  XXX
   --doh-path  <host>  XXX
   --doh-query <host>  XXX

```

Para obtener informacion de los comandos aceptados por el cliente, se debe ejecutar el cliente junto con el flag: "-h". Dicho flag hace que se listen las operaciones permitidas

```sh
user@user:~/TPE-Protos$ ./client5 -h
Usage: ./client5 [OPTIONS]... TOKEN [DESTINATION] [PORT]
Options:
-h                  imprime los comandos del programa y termina.
-r <user#pass>      agrega un usuario del proxy con el nombre y contraseña indicados.
-R <user#token>     agrega un usuario administrador con el nombre y token indicados.
-c                  imprime la cantidad de conexiones concurrentes del server.
-C                  imprime la cantidad de conexiones históricas del server.
-b                  imprime la cantidad de bytes transferidos del server.
-l                  imprime una lista con los usuarios del proxy.
-d <user>           borra el usuario del proxy con el nombre indicado.
-D <user>           borra el usuario administrador con el nombre indicado.
-O                  enciende el password disector en el server.
-F                  apaga el password disector en el server.
-v                  imprime la versión del programa y termina.

````

También, se puede acceder al manual ejecutando el siguiente comando en la raiz del proyecto

```sh
user@user:~/TPE-Protos$ man ./socks5d.8
socks5d(0.0.0)

NAME
       socks5d - proxy SOCKS versión 5 con esteroides

SINOPSIS
       socks5d [ POSIX style options ]

OPCIONES
       -h     Imprime la ayuda y termina.
       -l dirección-socks
              Establece la dirección donde servirá el proxy SOCKS.  Por defecto escucha en todas las interfaces.
       -N     Deshabilita los passwords disectors.
       -L dirección-de-management
              Establece la dirección donde servirá el servicio de management. Por defecto escucha únicamente en loopback.
       -p puerto-local
              Puerto TCP donde escuchará por conexiones entrantes SOCKS.  Por defecto el valor es 1080.
       -P puerto-conf
              Puerto SCTP  donde escuchará por conexiones entrante del protocolo de configuración. Por defecto el valor es 8080.
       -u user:pass
              Declara un usuario del proxy con su contraseña. Se puede utilizar hasta veces.
       -v     Imprime información sobre la versión versión y termina.

REGISTRO DE ACCESO
       Registra el uso del proxy en salida estandar. Una conexión por línea. Los campos de una línea separado por tabs:

       fecha  que se procesó la conexión en formato ISO-8601.  Ejemplo 2022-06-15T19:56:34Z.

       nombre de usuario
              que hace el requerimiento.  Ejemplo juan.

       tipo de registro
              Siempre el caracter A.

       direccion IP origen
              desde donde se conectó el usuario.  Ejemplo ::1.

       puerto origen
              desde donde se conectó el usuario.  Ejemplo 54786.

       destino
              a donde nos conectamos. nombre o dirección IP (según ATY).  Ejemplo www.itba.edu.ar.  Ejemplo ::1.
        
        puerto destino
              Ejemplo 443.

       status Status code de SOCKSv5. Ejemplo 0.

REGISTRO DE PASSWORDS
       Registra las credenciales descubiertas en salida estandar. Una credencial por línea.  Los campos de una línea separados por tabs:

       fecha  que se procesó la conexión en formato ISO-8601.  Ejemplo 2020-06-15T19:56:34Z.

       nombre de usuario
              que hace el requerimiento.  Ejemplo juan.

       tipo de registro
              Siempre el caracter P.

       protocolo
              Protocolo del que se trata. HTTP o POP3.

       destino
              a donde nos conectamos. nombre o dirección IP (según ATY).  Ejemplo www.itba.edu.ar.  Ejemplo ::1.

       puerto destino
              Ejemplo 443.

       usuario
              Usuario descubierto.

       password
              Password descubierta.
```

## Autores
- 61008 - Banfi, Malena
- 61153 - Fleischer, Lucas
- 61170 - Perez Rivera, Mateo
- 61171 - Szejer, Ian