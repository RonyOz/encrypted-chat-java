package com.encryptedchat.observer;

public enum EventType {
    // Handshake
    KEY_PAIR_GENERATED,
    HELLO_SENT,
    HELLO_RECEIVED,
    TRANSCRIPT_HASH,
    ECDH_SECRET,
    HKDF_EXTRACT,
    AES_KEY_DERIVED,
    CONFIRMATION_KEY_DERIVED,
    CONFIRMATION_SENT,
    CONFIRMATION_RECEIVED,
    FINGERPRINT,

    // Mensajes
    MSG_SENT,
    MSG_RECEIVED
}
