package com.encryptedchat.crypto;

public enum PeerRole {
    SERVER(0),
    CLIENT(1);

    private final int id;

    PeerRole(int id) {
        this.id = id;
    }

    int id() {
        return id;
    }

    PeerRole opposite() {
        return this == SERVER ? CLIENT : SERVER;
    }

    static PeerRole fromId(int id) {
        for (PeerRole role : values()) {
            if (role.id == id) {
                return role;
            }
        }
        throw new IllegalArgumentException("Rol de red desconocido: " + id);
    }
}

