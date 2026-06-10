package com.encryptedchat;

import com.encryptedchat.crypto.PeerRole;
import com.encryptedchat.crypto.SecureChannel;
import com.encryptedchat.crypto.SecureMessage;
import com.encryptedchat.observer.UdpEventEmitter;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicBoolean;

public final class ChatApplication {
    private static final int DEFAULT_PORT = 5050;
    private static final int CONNECT_TIMEOUT_MILLIS = 10_000;
    private static final int HANDSHAKE_TIMEOUT_MILLIS = 30_000;

    private ChatApplication() {
    }

    public static void main(String[] args) {
        int result = run(args);
        if (result != 0) {
            System.exit(result);
        }
    }

    static int run(String[] args) {
        final Config config;
        try {
            config = Config.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            printUsage();
            return 2;
        }

        if (config.help) {
            printUsage();
            return 0;
        }

        try (Socket socket = openSocket(config);
             UdpEventEmitter emitter = config.observe
                     ? new UdpEventEmitter(config.role.name()) : null) {
            socket.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
            System.out.println("Negociando clave mediante ECDH (secp256r1)...");
            if (config.observe) {
                System.out.println("[--observe activo] enviando eventos al observador en UDP :7777");
            }

            try (SecureChannel channel = SecureChannel.establish(socket, config.role, emitter)) {
                socket.setSoTimeout(0);
                System.out.println("Canal AES-" + channel.getEncryptionKeySizeBits()
                        + "-GCM establecido con " + socket.getRemoteSocketAddress());
                System.out.println("Codigo de seguridad: " + channel.getFingerprint());
                System.out.println("Compare este codigo con el otro usuario por un canal distinto.");

                channel.sendIntroduction(config.name);
                SecureMessage introduction = channel.read();
                if (introduction.getType() != SecureMessage.Type.INTRODUCTION
                        || introduction.getText().trim().isEmpty()) {
                    throw new GeneralSecurityException("El otro extremo no envio un nombre valido");
                }

                String peerName = introduction.getText();
                System.out.println("Conectado con " + peerName + ". Escriba /salir para terminar.");
                runConversation(channel, peerName);
            }
            return 0;
        } catch (GeneralSecurityException e) {
            System.err.println("Error criptografico: " + e.getMessage());
            return 3;
        } catch (IOException e) {
            System.err.println("Error de red: " + e.getMessage());
            return 4;
        }
    }

    private static Socket openSocket(Config config) throws IOException {
        if (config.role == PeerRole.CLIENT) {
            Socket socket = new Socket();
            System.out.println("Conectando con " + config.host + ":" + config.port + "...");
            socket.connect(new InetSocketAddress(config.host, config.port), CONNECT_TIMEOUT_MILLIS);
            socket.setTcpNoDelay(true);
            return socket;
        }

        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(config.bindAddress, config.port));
            System.out.println("Esperando una conexion en " + config.bindAddress + ":"
                    + config.port + "...");
            Socket socket = server.accept();
            socket.setTcpNoDelay(true);
            return socket;
        }
    }

    private static void runConversation(SecureChannel channel, String peerName)
            throws IOException, GeneralSecurityException {
        AtomicBoolean closing = new AtomicBoolean(false);
        Thread inputThread = new Thread(() -> readConsole(channel, closing), "chat-console-input");
        inputThread.setDaemon(true);
        inputThread.start();

        try {
            while (true) {
                SecureMessage message = channel.read();
                if (message.getType() == SecureMessage.Type.CHAT) {
                    System.out.println(peerName + ": " + message.getText());
                } else if (message.getType() == SecureMessage.Type.CLOSE) {
                    closing.set(true);
                    System.out.println(peerName + " cerro la conversacion.");
                    channel.sendClose();
                    return;
                } else {
                    throw new GeneralSecurityException(
                            "Se recibio una segunda presentacion inesperada");
                }
            }
        } catch (EOFException e) {
            if (!closing.get()) {
                throw new IOException("La conexion se cerro sin un mensaje de despedida", e);
            }
        } finally {
            closing.set(true);
        }
    }

    private static void readConsole(SecureChannel channel, AtomicBoolean closing) {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));
        try {
            String line;
            while (!closing.get() && (line = reader.readLine()) != null) {
                if ("/salir".equalsIgnoreCase(line.trim())) {
                    channel.sendClose();
                    closing.set(true);
                    return;
                }
                try {
                    channel.sendChat(line);
                } catch (IllegalArgumentException e) {
                    System.err.println("No se pudo enviar el mensaje: " + e.getMessage());
                }
            }
            if (!closing.get()) {
                channel.sendClose();
                closing.set(true);
            }
        } catch (IOException | GeneralSecurityException e) {
            if (closing.compareAndSet(false, true)) {
                System.err.println("No se pudo enviar el mensaje: " + e.getMessage());
                try {
                    channel.close();
                } catch (IOException ignored) {
                    // El error original es el relevante para el usuario.
                }
            }
        }
    }

    private static void printUsage() {
        System.out.println("Uso:");
        System.out.println("  Servidor: java -jar encrypted-chat.jar server"
                + " [--port 5050] [--bind 0.0.0.0] [--name Nombre]");
        System.out.println("  Cliente:  java -jar encrypted-chat.jar client --host IP"
                + " [--port 5050] [--name Nombre]");
        System.out.println("  Ayuda:    java -jar encrypted-chat.jar --help");
    }

    private static final class Config {
        private final PeerRole role;
        private final String host;
        private final String bindAddress;
        private final int port;
        private final String name;
        private final boolean help;
        private final boolean observe;

        private Config(
                PeerRole role,
                String host,
                String bindAddress,
                int port,
                String name,
                boolean help,
                boolean observe) {
            this.role = role;
            this.host = host;
            this.bindAddress = bindAddress;
            this.port = port;
            this.name = name;
            this.help = help;
            this.observe = observe;
        }

        private static Config parse(String[] args) {
            if (args.length == 0) {
                throw new IllegalArgumentException("Debe indicar server o client");
            }
            if (args.length == 1 && ("--help".equals(args[0]) || "-h".equals(args[0]))) {
                return new Config(null, null, null, DEFAULT_PORT, null, true, false);
            }

            PeerRole role;
            if ("server".equalsIgnoreCase(args[0])) {
                role = PeerRole.SERVER;
            } else if ("client".equalsIgnoreCase(args[0])) {
                role = PeerRole.CLIENT;
            } else {
                throw new IllegalArgumentException("Modo desconocido: " + args[0]);
            }

            String host = null;
            String bindAddress = "0.0.0.0";
            int port = DEFAULT_PORT;
            String name = System.getProperty("user.name", "Usuario");
            boolean observe = false;

            for (int i = 1; i < args.length; i++) {
                String option = args[i];
                if ("--observe".equals(option)) {
                    observe = true;
                    continue;
                }
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("Falta el valor de " + option);
                }
                String value = args[++i];
                switch (option) {
                    case "--host":
                        host = requireText(option, value);
                        break;
                    case "--bind":
                        bindAddress = requireText(option, value);
                        break;
                    case "--port":
                        port = parsePort(value);
                        break;
                    case "--name":
                        name = requireText(option, value);
                        break;
                    default:
                        throw new IllegalArgumentException("Opcion desconocida: " + option);
                }
            }

            if (role == PeerRole.CLIENT && host == null) {
                throw new IllegalArgumentException("El cliente requiere --host IP");
            }
            if (role == PeerRole.SERVER && host != null) {
                throw new IllegalArgumentException("--host solo se usa en modo client");
            }
            if (role == PeerRole.CLIENT && !"0.0.0.0".equals(bindAddress)) {
                throw new IllegalArgumentException("--bind solo se usa en modo server");
            }
            if (name.getBytes(StandardCharsets.UTF_8).length > 128) {
                throw new IllegalArgumentException("El nombre no puede superar 128 bytes UTF-8");
            }
            return new Config(role, host, bindAddress, port, name, false, observe);
        }

        private static String requireText(String option, String value) {
            if (value.trim().isEmpty()) {
                throw new IllegalArgumentException(option + " no puede estar vacio");
            }
            return value;
        }

        private static int parsePort(String value) {
            try {
                int parsed = Integer.parseInt(value);
                if (parsed < 1 || parsed > 65535) {
                    throw new IllegalArgumentException("El puerto debe estar entre 1 y 65535");
                }
                return parsed;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Puerto invalido: " + value, e);
            }
        }
    }
}

