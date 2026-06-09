# Encrypted Chat Java

> Aplicacion de chat cifrado peer-to-peer con intercambio de claves ECDH y cifrado AES-256-GCM.

[Informe completo →](docs/informe.md)

## Descripcion

Chat de consola en Java puro (sin dependencias externas) que permite a dos usuarios comunicarse de forma segura a traves de una red TCP. Implementa cifrado de extremo a extremo usando criptografia de curva eliptica y AES.

## Esquema de criptografía

![Arquitectura criptografica](docs/crypto-architecture.png)

## Caracteristicas

- **ECDH secp256r1** — Intercambio de claves mediante curva eliptica P-256
- **AES-256-GCM** — Cifrado autenticado de mensajes (confidencialidad + integridad)
- **HKDF-SHA-256** — Derivacion de claves segura (RFC 5869)
- **Claves efimeras** — Perfect Forward Secrecy (PFS)
- **Sin dependencias** — Solo utiliza el JDK estandar (Java 11+)

## Compilacion

```bash
./scripts/build.sh
```

## Ejecucion

```bash
# Servidor
java -jar build/encrypted-chat.jar server --port 5050 --name Alice

# Cliente
java -jar build/encrypted-chat.jar client --host 192.168.1.10 --port 5050 --name Bob
```

## Tests

```bash
./scripts/test.sh
```

## Autores

- **Autor 1**
- **Autor 2**
- **Autor 3**

## Licencia

Proyecto academico.
