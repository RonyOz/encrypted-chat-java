package com.encryptedchat.crypto;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public final class CryptoSelfTest {
    private CryptoSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        testHkdfRfc5869Vector();
        testEncryptedConversationOverTcp();
        System.out.println("OK: todas las pruebas pasaron");
    }

    private static void testHkdfRfc5869Vector() throws Exception {
        byte[] inputKeyMaterial = new byte[22];
        Arrays.fill(inputKeyMaterial, (byte) 0x0b);
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] expectedPrk = hex(
                "077709362c2e32df0ddc3f0dc47bba63"
                        + "90b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] expectedOkm = hex(
                "3cb25f25faacd57a90434f64d0362f2a"
                        + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865");

        byte[] actualPrk = Hkdf.extract(salt, inputKeyMaterial);
        byte[] actualOkm = Hkdf.expand(actualPrk, info, 42);
        assertArrayEquals(expectedPrk, actualPrk, "HKDF-Extract");
        assertArrayEquals(expectedOkm, actualOkm, "HKDF-Expand");
    }

    private static void testEncryptedConversationOverTcp() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try (ServerSocket listener = new ServerSocket(0, 1, loopback)) {
            Future<SessionResult> server = executor.submit(() -> {
                try (Socket socket = listener.accept();
                        SecureChannel channel = SecureChannel.establish(socket, PeerRole.SERVER)) {
                    assertEquals(256, channel.getEncryptionKeySizeBits(), "tamano de clave servidor");
                    channel.sendIntroduction("Servidor");
                    assertMessage(channel.read(), SecureMessage.Type.INTRODUCTION, "Cliente");
                    channel.sendChat("mensaje secreto del servidor");
                    assertMessage(channel.read(), SecureMessage.Type.CHAT, "respuesta secreta");
                    channel.sendClose();
                    assertMessage(channel.read(), SecureMessage.Type.CLOSE, "");
                    return new SessionResult(channel.getFingerprint());
                }
            });

            Future<SessionResult> client = executor.submit(() -> {
                try (Socket socket = new Socket(loopback, listener.getLocalPort());
                        SecureChannel channel = SecureChannel.establish(socket, PeerRole.CLIENT)) {
                    assertEquals(256, channel.getEncryptionKeySizeBits(), "tamano de clave cliente");
                    channel.sendIntroduction("Cliente");
                    assertMessage(channel.read(), SecureMessage.Type.INTRODUCTION, "Servidor");
                    assertMessage(
                            channel.read(), SecureMessage.Type.CHAT, "mensaje secreto del servidor");
                    channel.sendChat("respuesta secreta");
                    assertMessage(channel.read(), SecureMessage.Type.CLOSE, "");
                    channel.sendClose();
                    return new SessionResult(channel.getFingerprint());
                }
            });

            SessionResult serverResult = server.get(10, TimeUnit.SECONDS);
            SessionResult clientResult = client.get(10, TimeUnit.SECONDS);
            assertEquals(
                    serverResult.fingerprint,
                    clientResult.fingerprint,
                    "huella de sesion compartida");
        } finally {
            executor.shutdownNow();
        }
    }

    private static void assertMessage(
            SecureMessage actual, SecureMessage.Type expectedType, String expectedText) {
        assertEquals(expectedType, actual.getType(), "tipo de mensaje");
        assertEquals(expectedText, actual.getText(), "contenido de mensaje");
    }

    private static void assertArrayEquals(byte[] expected, byte[] actual, String description) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(description + " no coincide");
        }
    }

    private static void assertEquals(Object expected, Object actual, String description) {
        if (!expected.equals(actual)) {
            throw new AssertionError(
                    description + ": esperado=" + expected + ", actual=" + actual);
        }
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int offset = i * 2;
            result[i] = (byte) Integer.parseInt(value.substring(offset, offset + 2), 16);
        }
        return result;
    }

    private static final class SessionResult {
        private final String fingerprint;

        private SessionResult(String fingerprint) {
            this.fingerprint = fingerprint;
        }
    }
}

