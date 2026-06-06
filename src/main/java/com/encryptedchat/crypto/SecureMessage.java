package com.encryptedchat.crypto;

public final class SecureMessage {
    public enum Type {
        INTRODUCTION(1),
        CHAT(2),
        CLOSE(3);

        private final int id;

        Type(int id) {
            this.id = id;
        }

        int id() {
            return id;
        }

        static Type fromId(int id) {
            for (Type type : values()) {
                if (type.id == id) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Tipo de mensaje desconocido: " + id);
        }
    }

    private final Type type;
    private final String text;

    SecureMessage(Type type, String text) {
        this.type = type;
        this.text = text;
    }

    public Type getType() {
        return type;
    }

    public String getText() {
        return text;
    }
}

