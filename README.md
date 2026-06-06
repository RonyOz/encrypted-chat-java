# Chat cifrado en Java

Aplicación de consola para comunicar dos computadores mediante TCP. Al conectarse,
las instancias generan claves efímeras ECDH sobre `secp256r1`, derivan una clave de
256 bits con HKDF-SHA-256 y cifran todos los mensajes posteriores con AES-256-GCM.

No utiliza bibliotecas externas. Requiere JDK 11 o superior.

## Compilar y probar

```bash
chmod +x scripts/*.sh
./scripts/test.sh
```

El archivo distribuible queda en `build/encrypted-chat.jar`. Debe copiarse ese mismo
archivo a los dos computadores.

## Ejecutar en dos computadores

En el computador que recibirá la conexión:

```bash
java -jar encrypted-chat.jar server --port 5050 --name Alicia
```

En el otro computador, usando la dirección IP del primero:

```bash
java -jar encrypted-chat.jar client --host 192.168.1.25 --port 5050 --name Bruno
```

El puerto TCP elegido debe estar permitido por el firewall del servidor. En una red
local, ambos equipos deben poder alcanzarse entre sí. Para comunicar redes distintas
se necesita una VPN o configurar el reenvío del puerto en el router.

Escriba `/salir` para cerrar la sesión de manera ordenada.

## Verificación de seguridad

Ambas instancias muestran el mismo **código de seguridad** después del intercambio
ECDH. Los usuarios deben compararlo por un canal distinto, por ejemplo una llamada.
ECDH por sí solo no autentica a los participantes: si no se compara este código, un
atacante activo en la red podría intentar un ataque de intermediario.

## Protocolo implementado

1. Se abre una conexión TCP entre servidor y cliente.
2. Cada instancia genera un par de claves EC efímero sobre `secp256r1`.
3. Intercambian y validan las claves públicas codificadas como X.509.
4. ECDH produce el secreto compartido.
5. HKDF-SHA-256 usa el transcript de conexión como `salt` y deriva una clave AES de
   32 bytes, es decir, 256 bits, además de una clave separada de confirmación.
6. Ambos extremos confirman que derivaron la misma clave mediante HMAC-SHA-256.
7. Nombres, mensajes y cierre se transmiten con AES-256-GCM y etiqueta de 128 bits.
8. Cada dirección usa un espacio de `nonce` independiente y un contador de 64 bits.

AES-GCM también verifica la integridad: una trama alterada, repetida o fuera de orden
se rechaza y la sesión termina. Las claves son efímeras y no se guardan en disco.

Más detalles técnicos están en [docs/diseno.md](docs/diseno.md).

