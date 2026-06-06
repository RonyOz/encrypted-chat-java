# Diseño técnico

## Arquitectura

La aplicación tiene un único ejecutable con dos modos:

- `server`: escucha una conexión TCP en la dirección y puerto indicados.
- `client`: inicia la conexión TCP contra el servidor.

Después de aceptar la conexión, ambos modos ejecutan exactamente el mismo protocolo
criptográfico, cambiando únicamente los identificadores de dirección usados por los
contadores de AES-GCM.

## Negociación de clave

Cada extremo genera un par de claves efímeras sobre la curva NIST P-256, identificada
en Java como `secp256r1`. Las claves públicas se intercambian junto con la versión del
protocolo y el rol. Se comprueba que la clave recibida pertenece a la curva esperada.

El secreto ECDH no se usa directamente como clave. Se procesa con HKDF-SHA-256:

```text
salt = SHA-256(saludoServidor || saludoCliente)
PRK  = HKDF-Extract(salt, secretoECDH)
K    = HKDF-Expand(PRK, "encrypted-chat/aes-256-gcm/v1", 32)
```

`K` tiene 32 bytes, equivalentes a 256 bits. Otra salida HKDF independiente se usa
para confirmar mediante HMAC que ambos extremos calcularon el mismo material secreto.

## Cifrado de mensajes

Cada mensaje se representa como un byte de tipo seguido por texto UTF-8. La estructura
completa se cifra con `AES/GCM/NoPadding`. Esto incluye la presentación con el nombre,
los mensajes de chat y la señal de cierre.

El `nonce` GCM tiene 96 bits:

```text
32 bits: identificador fijo de dirección
64 bits: contador creciente de mensajes
```

Servidor a cliente y cliente a servidor usan identificadores distintos. El receptor
exige el contador exacto esperado. La versión del protocolo y el `nonce` se agregan
como datos autenticados adicionales (AAD).

## Propiedades y alcance

- Confidencialidad: AES-256-GCM.
- Integridad y autenticidad de cada trama dentro de la sesión: etiqueta GCM de 128 bits.
- Secreto efímero: se genera un nuevo par ECDH en cada conexión.
- Confirmación de clave: HMAC-SHA-256 antes de iniciar el chat.
- Detección de repetición y reordenamiento: contador autenticado por dirección.

La aplicación no usa certificados ni una autoridad de confianza. Por eso muestra una
huella corta de la sesión que debe compararse por un canal externo para detectar un
posible intermediario activo.
