package com.encryptedchat.observer;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

public final class UdpEventEmitter implements AutoCloseable {
    private static final int OBSERVER_PORT = 7777;
    private static final int MAX_PACKET = 8192;

    private final DatagramSocket socket;
    private final InetAddress localhost;
    private final String role;

    public UdpEventEmitter(String role) {
        this.role = role;
        DatagramSocket s = null;
        InetAddress addr = null;
        try {
            s = new DatagramSocket();
            String host = System.getenv("OBSERVER_HOST");
            addr = (host != null && !host.isEmpty())
                    ? InetAddress.getByName(host)
                    : InetAddress.getLoopbackAddress();
        } catch (Exception ignored) {
        }
        this.socket = s;
        this.localhost = addr;
    }

    public void emit(EventType type, String... keyValues) {
        if (socket == null || localhost == null) return;
        try {
            StringBuilder json = new StringBuilder("{");
            json.append("\"role\":\"").append(role).append("\",");
            json.append("\"type\":\"").append(type.name()).append("\"");
            for (int i = 0; i + 1 < keyValues.length; i += 2) {
                json.append(",\"").append(keyValues[i]).append("\":\"")
                    .append(keyValues[i + 1]).append("\"");
            }
            json.append("}");

            byte[] data = json.toString().getBytes(StandardCharsets.UTF_8);
            if (data.length > MAX_PACKET) return;
            DatagramPacket packet = new DatagramPacket(data, data.length, localhost, OBSERVER_PORT);
            socket.send(packet);
        } catch (Exception ignored) {
        }
    }

    public static String hex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }

    public static String hexPlain(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    @Override
    public void close() {
        if (socket != null) socket.close();
    }
}
