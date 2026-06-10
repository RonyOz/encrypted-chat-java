package com.encryptedchat.observer;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class SessionObserverApp {
    private static final int PORT = 7777;
    private static final int BUF = 8192;

    // Colores ANSI
    private static final String RESET  = "[0m";
    private static final String CYAN   = "[36m";
    private static final String GREEN  = "[32m";
    private static final String YELLOW = "[33m";
    private static final String RED    = "[31m";
    private static final String GRAY   = "[90m";
    private static final String BOLD   = "[1m";
    private static final String WHITE  = "[97m";

    public static void main(String[] args) throws Exception {
        printBanner();
        try (DatagramSocket socket = new DatagramSocket(PORT)) {
            byte[] buf = new byte[BUF];
            while (true) {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);
                String json = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8);
                try {
                    Map<String, String> event = parseJson(json);
                    handleEvent(event);
                } catch (Exception e) {
                    System.out.println(RED + "[error parseando evento: " + e.getMessage() + "]" + RESET);
                }
            }
        }
    }

    private static void handleEvent(Map<String, String> e) {
        String type = e.getOrDefault("type", "");
        String role = e.getOrDefault("role", "?");

        switch (type) {
            case "KEY_PAIR_GENERATED":
                printHandshakeHeader();
                printCrypto(role, "Clave publica EC generada (A = a×G)",
                        e.get("publicKey"), "65 bytes — se envia al otro extremo");
                break;

            case "HELLO_SENT":
                printCrypto(role, "Hello enviado",
                        truncate(e.get("bytes"), 60), "magic + version + rol + clave publica");
                printAttacker(role, "HELLO_SENT", e.get("bytes"));
                break;

            case "HELLO_RECEIVED":
                printCrypto(role, "Hello recibido",
                        truncate(e.get("bytes"), 60), "del otro extremo");
                printAttacker(role, "HELLO_RECEIVED", e.get("bytes"));
                break;

            case "TRANSCRIPT_HASH":
                printCrypto(role, "Transcript hash (sal HKDF)",
                        e.get("hash"), "SHA-256 de ambos hellos — unico por sesion");
                break;

            case "ECDH_SECRET":
                printEcdhBox(role, e.get("secret"));
                break;

            case "HKDF_EXTRACT":
                printCrypto(role, "HKDF extract → PRK",
                        e.get("prk"), "secreto ECDH + sal → bytes uniformes");
                break;

            case "AES_KEY_DERIVED":
                printCrypto(role, "Clave AES-256 derivada",
                        e.get("key"), "32 bytes — cifra todos los mensajes");
                break;

            case "CONFIRMATION_KEY_DERIVED":
                printCrypto(role, "Clave de confirmacion derivada",
                        e.get("key"), "32 bytes — verifica que ambos lados coinciden");
                break;

            case "CONFIRMATION_SENT":
                printCrypto(role, "HMAC de confirmacion enviado",
                        truncate(e.get("hmac"), 60), "");
                break;

            case "CONFIRMATION_RECEIVED":
                boolean valid = "true".equals(e.get("valid"));
                String validStr = valid
                        ? GREEN + "✓ CLAVES COINCIDEN — sin MITM detectado" + RESET
                        : RED + "✗ FALLO — claves distintas, posible MITM" + RESET;
                printCrypto(role, "HMAC de confirmacion recibido",
                        truncate(e.get("hmac"), 60), "");
                System.out.println("  " + validStr);
                break;

            case "FINGERPRINT":
                printFingerprintBox(role, e.get("value"));
                break;

            case "MSG_SENT":
            case "MSG_RECEIVED":
                printMessageEvent(e, type.equals("MSG_SENT"));
                break;

            default:
                System.out.println(GRAY + "[evento desconocido: " + type + "]" + RESET);
        }
    }

    // ── Secciones visuales ───────────────────────────────────────────────────

    private static boolean handshakeHeaderPrinted = false;

    private static void printBanner() {
        System.out.println(BOLD + CYAN);
        System.out.println("╔" + repeat("═", 62) + "╗");
        System.out.println("║   OBSERVADOR DE SESION COMBINADO" + pad(28) + "║");
        System.out.println("║   Escuchando eventos en UDP :" + PORT + pad(31) + "║");
        System.out.println("╚" + repeat("═", 62) + "╝");
        System.out.println(RESET);
    }

    private static void printHandshakeHeader() {
        if (handshakeHeaderPrinted) return;
        handshakeHeaderPrinted = true;
        System.out.println(BOLD + YELLOW + "\n" + repeat("─", 64) + RESET);
        System.out.println(BOLD + YELLOW + "  HANDSHAKE" + RESET);
        System.out.println(BOLD + YELLOW + repeat("─", 64) + RESET);
    }

    private static void printCrypto(String role, String label, String value, String note) {
        System.out.println(CYAN + "  [" + role + "] " + WHITE + label + RESET);
        if (value != null && !value.isEmpty()) {
            System.out.println(GREEN + "         " + value + RESET);
        }
        if (note != null && !note.isEmpty()) {
            System.out.println(GRAY + "         → " + note + RESET);
        }
    }

    private static void printEcdhBox(String role, String secret) {
        System.out.println();
        System.out.println(BOLD + RED + "  ┌" + repeat("─", 58) + "┐" + RESET);
        System.out.println(BOLD + RED + "  │  [" + role + "] SECRETO ECDH (a×b×G)" + pad(38) + "│" + RESET);
        System.out.println(GREEN + "  │  " + truncate(secret, 52) + pad(Math.max(0, 54 - truncate(secret, 52).length())) + RED + BOLD + "│" + RESET);
        System.out.println(BOLD + YELLOW + "  │  ⚠  Este valor NUNCA sale por la red" + pad(22) + RED + "│" + RESET);
        System.out.println(BOLD + RED + "  └" + repeat("─", 58) + "┘" + RESET);
        System.out.println();
    }

    private static void printFingerprintBox(String role, String fingerprint) {
        System.out.println();
        System.out.println(BOLD + GREEN + "  ┌" + repeat("─", 50) + "┐" + RESET);
        System.out.println(BOLD + GREEN + "  │  Fingerprint [" + role + "]: " + WHITE + fingerprint + pad(Math.max(0, 34 - fingerprint.length())) + GREEN + "│" + RESET);
        System.out.println(BOLD + GREEN + "  │  Comparar con el otro usuario fuera de banda" + pad(4) + "│" + RESET);
        System.out.println(BOLD + GREEN + "  └" + repeat("─", 50) + "┘" + RESET);
        System.out.println();
        System.out.println(BOLD + YELLOW + repeat("─", 64) + RESET);
        System.out.println(BOLD + YELLOW + "  MENSAJES" + RESET);
        System.out.println(BOLD + YELLOW + repeat("─", 30) + "╤" + repeat("─", 33) + RESET);
        System.out.println(BOLD + "  VISTA CRIPTOGRAFICA" + pad(10) + YELLOW + "║" + RESET + BOLD + "  VISTA DEL ATACANTE" + RESET);
        System.out.println(BOLD + YELLOW + repeat("─", 30) + "╪" + repeat("─", 33) + RESET);
    }

    private static void printAttacker(String role, String direction, String bytes) {
        System.out.println(GRAY + "  ║  " + direction + " [" + role + "]: " + truncate(bytes, 40) + RESET);
    }

    private static void printMessageEvent(Map<String, String> e, boolean sent) {
        String role    = e.getOrDefault("role", "?");
        String counter = e.getOrDefault("counter", "?");
        String msgType = e.getOrDefault("msgType", "?");
        String text    = e.getOrDefault("text", "");
        String nonce   = e.getOrDefault("nonce", "");
        String plain   = e.getOrDefault("plaintext", "");
        String cipher  = e.getOrDefault("ciphertext", "");
        String tag     = e.getOrDefault("tag", "");
        String frame   = e.getOrDefault("frame", "");

        String dir = sent ? CYAN + "ENVIADO" : YELLOW + "RECIBIDO";

        // Columna izquierda: vista criptografica
        System.out.println();
        System.out.println(BOLD + "  #" + counter + " [" + role + "] " + dir + RESET
                + BOLD + " [" + msgType + "]" + RESET);

        if (!text.isEmpty() && !"CLOSE".equals(msgType)) {
            System.out.println(WHITE  + "  Texto   : \"" + text + "\"" + RESET);
        }
        System.out.println(GREEN  + "  Nonce   : " + formatNonce(nonce) + RESET);
        System.out.println(GREEN  + "  Plaintext: " + truncate(plain, 48) + RESET);
        System.out.println(GRAY   + "  Cifrado : " + truncate(cipher, 48) + RESET);
        System.out.println(GRAY   + "  Tag GCM : " + truncate(tag, 48) + RESET);

        // Columna derecha: vista del atacante
        System.out.println(BOLD + YELLOW + "  │" + RESET + GRAY + " Frame TCP (" + frameBytes(frame) + " bytes):" + RESET);
        if (!frame.isEmpty()) {
            String[] parts = frame.split(" ");
            printFrameLine("  │ contador : ", parts, 0, 8);
            printFrameLine("  │ longitud : ", parts, 8, 4);
            printFrameLine("  │ payload  : ", parts, 12, Math.min(parts.length - 12, 11));
            if (parts.length > 23) {
                printFrameLine("  │ tag GCM  : ", parts, parts.length - 16, 16);
            }
        }
        System.out.println(BOLD + YELLOW + repeat("─", 30) + "╪" + repeat("─", 33) + RESET);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static String formatNonce(String nonce) {
        String[] parts = nonce.split(":");
        if (parts.length < 12) return nonce;
        StringBuilder prefix = new StringBuilder();
        StringBuilder counter = new StringBuilder();
        for (int i = 0; i < 4; i++) { if (i > 0) prefix.append(':'); prefix.append(parts[i]); }
        for (int i = 4; i < 12; i++) { if (i > 4) counter.append(':'); counter.append(parts[i]); }
        return prefix + GRAY + " | " + RESET + GREEN + counter;
    }

    private static void printFrameLine(String label, String[] parts, int from, int count) {
        StringBuilder sb = new StringBuilder();
        int end = Math.min(from + count, parts.length);
        for (int i = from; i < end; i++) {
            if (i > from) sb.append(' ');
            sb.append(parts[i]);
        }
        System.out.println(BOLD + YELLOW + label + RESET + GRAY + sb + RESET);
    }

    private static int frameBytes(String frame) {
        if (frame == null || frame.isEmpty()) return 0;
        return frame.split(" ").length;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + GRAY + "..." + RESET;
    }

    private static String pad(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(' ');
        return sb.toString();
    }

    private static String repeat(String c, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(c);
        return sb.toString();
    }

    // Parseo JSON minimalista: solo soporta objetos planos con valores string
    private static Map<String, String> parseJson(String json) {
        Map<String, String> map = new LinkedHashMap<>();
        json = json.trim();
        if (json.startsWith("{")) json = json.substring(1);
        if (json.endsWith("}")) json = json.substring(0, json.length() - 1);

        int i = 0;
        while (i < json.length()) {
            // saltar espacios y comas
            while (i < json.length() && (json.charAt(i) == ',' || json.charAt(i) == ' ')) i++;
            if (i >= json.length()) break;

            // leer clave
            if (json.charAt(i) != '"') break;
            int keyStart = i + 1;
            int keyEnd = json.indexOf('"', keyStart);
            String key = json.substring(keyStart, keyEnd);
            i = keyEnd + 1;

            // saltar ':'
            while (i < json.length() && json.charAt(i) != ':') i++;
            i++;
            while (i < json.length() && json.charAt(i) == ' ') i++;

            // leer valor
            if (i >= json.length()) break;
            String value;
            if (json.charAt(i) == '"') {
                int valStart = i + 1;
                int valEnd = valStart;
                while (valEnd < json.length()) {
                    if (json.charAt(valEnd) == '\\') { valEnd += 2; continue; }
                    if (json.charAt(valEnd) == '"') break;
                    valEnd++;
                }
                value = json.substring(valStart, valEnd)
                        .replace("\\\"", "\"")
                        .replace("\\\\", "\\");
                i = valEnd + 1;
            } else {
                int valEnd = i;
                while (valEnd < json.length() && json.charAt(valEnd) != ',' && json.charAt(valEnd) != '}') valEnd++;
                value = json.substring(i, valEnd).trim();
                i = valEnd;
            }
            map.put(key, value);
        }
        return map;
    }
}
