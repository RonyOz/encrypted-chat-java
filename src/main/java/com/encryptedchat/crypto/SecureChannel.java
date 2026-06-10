package com.encryptedchat.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class SecureChannel implements Closeable {
    private static final int MAGIC = 0x45434831; // ECH1
    private static final int VERSION = 1;
    private static final int MAX_HELLO_LENGTH = 2048;
    private static final int MAX_PAYLOAD_LENGTH = 64 * 1024;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = GCM_TAG_BITS / 8;
    private static final int AES_KEY_BYTES = 32;
    private static final int CONFIRMATION_BYTES = 32;
    private static final byte[] HKDF_INFO =
            "encrypted-chat/aes-256-gcm/v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CONFIRMATION_INFO =
            "encrypted-chat/key-confirmation/v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] FINGERPRINT_LABEL =
            "encrypted-chat/fingerprint/v1".getBytes(StandardCharsets.US_ASCII);

    private final Socket socket;
    private final DataInputStream input;
    private final DataOutputStream output;
    private final SecretKeySpec aesKey;
    private final PeerRole localRole;
    private final String fingerprint;
    private final Object sendLock = new Object();
    private long sendCounter;
    private long receiveCounter;
    private boolean closeSent;

    private SecureChannel(
            Socket socket,
            DataInputStream input,
            DataOutputStream output,
            SecretKeySpec aesKey,
            PeerRole localRole,
            String fingerprint) {
        this.socket = socket;
        this.input = input;
        this.output = output;
        this.aesKey = aesKey;
        this.localRole = localRole;
        this.fingerprint = fingerprint;
    }

    public static SecureChannel establish(Socket socket, PeerRole localRole)
            throws IOException, GeneralSecurityException {
        DataInputStream input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        DataOutputStream output = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

        KeyPair keyPair = generateKeyPair();
        byte[] localHello = encodeHello(localRole, keyPair.getPublic().getEncoded());
        writeBlob(output, localHello);
        output.flush();

        byte[] peerHello = readBlob(input, MAX_HELLO_LENGTH, "saludo ECDH");
        DecodedHello decodedPeer = decodeHello(peerHello);
        if (decodedPeer.role != localRole.opposite()) {
            throw new GeneralSecurityException("Ambos extremos intentaron usar el mismo rol");
        }

        PublicKey peerPublicKey = decodeAndValidatePublicKey(decodedPeer.publicKey, keyPair);
        byte[] transcript = localRole == PeerRole.SERVER
                ? concatenate(localHello, peerHello)
                : concatenate(peerHello, localHello);
        byte[] transcriptHash = MessageDigest.getInstance("SHA-256").digest(transcript);

        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(keyPair.getPrivate());
        agreement.doPhase(peerPublicKey, true);
        byte[] sharedSecret = agreement.generateSecret();
        byte[] pseudoRandomKey = Hkdf.extract(transcriptHash, sharedSecret);
        byte[] aesKeyBytes = Hkdf.expand(pseudoRandomKey, HKDF_INFO, AES_KEY_BYTES);
        byte[] confirmationKey = Hkdf.expand(
                pseudoRandomKey, CONFIRMATION_INFO, CONFIRMATION_BYTES);

        try {
            confirmKey(output, input, confirmationKey, transcript, localRole);
            String fingerprint = createFingerprint(aesKeyBytes, transcriptHash);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            return new SecureChannel(socket, input, output, aesKey, localRole, fingerprint);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            Arrays.fill(pseudoRandomKey, (byte) 0);
            Arrays.fill(aesKeyBytes, (byte) 0);
            Arrays.fill(confirmationKey, (byte) 0);
        }
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public int getEncryptionKeySizeBits() {
        return AES_KEY_BYTES * 8;
    }

    public void sendIntroduction(String name) throws IOException, GeneralSecurityException {
        send(SecureMessage.Type.INTRODUCTION, name);
    }

    public void sendChat(String message) throws IOException, GeneralSecurityException {
        send(SecureMessage.Type.CHAT, message);
    }

    public void sendClose() throws IOException, GeneralSecurityException {
        synchronized (sendLock) {
            if (closeSent) {
                return;
            }
            sendLocked(SecureMessage.Type.CLOSE, "");
            closeSent = true;
        }
    }

    public SecureMessage read() throws IOException, GeneralSecurityException {
        long wireCounter = input.readLong();
        if (wireCounter != receiveCounter) {
            throw new GeneralSecurityException(
                    "Secuencia de mensajes invalida. Esperado " + receiveCounter
                            + ", recibido " + wireCounter);
        }

        int encryptedLength = input.readInt();
        int maxEncryptedLength = MAX_PAYLOAD_LENGTH + 1 + GCM_TAG_BYTES;
        if (encryptedLength < 1 + GCM_TAG_BYTES || encryptedLength > maxEncryptedLength) {
            throw new IOException("Longitud de trama cifrada invalida: " + encryptedLength);
        }

        byte[] encrypted = new byte[encryptedLength];
        input.readFully(encrypted);
        byte[] nonce = nonceFor(localRole.opposite(), receiveCounter);
        byte[] plaintext;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aadFor(nonce));
            plaintext = cipher.doFinal(encrypted);
        } catch (AEADBadTagException e) {
            throw new GeneralSecurityException(
                    "El mensaje fue alterado o la clave de sesion no coincide", e);
        }

        incrementReceiveCounter();
        if (plaintext.length < 1) {
            throw new GeneralSecurityException("Mensaje descifrado vacio");
        }

        SecureMessage.Type type;
        try {
            type = SecureMessage.Type.fromId(Byte.toUnsignedInt(plaintext[0]));
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }

        byte[] payload = Arrays.copyOfRange(plaintext, 1, plaintext.length);
        if (type == SecureMessage.Type.CLOSE && payload.length != 0) {
            throw new GeneralSecurityException("El mensaje de cierre contiene datos inesperados");
        }
        return new SecureMessage(type, decodeUtf8(payload));
    }

    private void send(SecureMessage.Type type, String text)
            throws IOException, GeneralSecurityException {
        synchronized (sendLock) {
            if (closeSent) {
                throw new IOException("El canal ya esta cerrandose");
            }
            sendLocked(type, text);
        }
    }

    private void sendLocked(SecureMessage.Type type, String text)
            throws IOException, GeneralSecurityException {
        byte[] payload = text.getBytes(StandardCharsets.UTF_8);
        if (payload.length > MAX_PAYLOAD_LENGTH) {
            throw new IllegalArgumentException(
                    "El mensaje supera el limite de " + MAX_PAYLOAD_LENGTH + " bytes UTF-8");
        }

        byte[] plaintext = new byte[payload.length + 1];
        plaintext[0] = (byte) type.id();
        System.arraycopy(payload, 0, plaintext, 1, payload.length);

        byte[] nonce = nonceFor(localRole, sendCounter);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(aadFor(nonce));
        byte[] encrypted = cipher.doFinal(plaintext);

        output.writeLong(sendCounter);
        output.writeInt(encrypted.length);
        output.write(encrypted);
        output.flush();
        incrementSendCounter();
    }

    private static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return generator.generateKeyPair();
    }

    private static byte[] encodeHello(PeerRole role, byte[] publicKey) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(bytes);
        data.writeInt(MAGIC);
        data.writeByte(VERSION);
        data.writeByte(role.id());
        data.writeInt(publicKey.length);
        data.write(publicKey);
        data.flush();
        return bytes.toByteArray();
    }

    private static DecodedHello decodeHello(byte[] hello)
            throws IOException, GeneralSecurityException {
        DataInputStream data = new DataInputStream(new ByteArrayInputStream(hello));
        if (data.readInt() != MAGIC) {
            throw new GeneralSecurityException("El otro extremo no usa el protocolo esperado");
        }
        int version = data.readUnsignedByte();
        if (version != VERSION) {
            throw new GeneralSecurityException("Version de protocolo no compatible: " + version);
        }

        PeerRole role;
        try {
            role = PeerRole.fromId(data.readUnsignedByte());
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }

        int publicKeyLength = data.readInt();
        if (publicKeyLength <= 0 || publicKeyLength > MAX_HELLO_LENGTH
                || publicKeyLength != data.available()) {
            throw new GeneralSecurityException("Longitud de clave publica invalida");
        }
        byte[] publicKey = new byte[publicKeyLength];
        data.readFully(publicKey);
        return new DecodedHello(role, publicKey);
    }

    private static PublicKey decodeAndValidatePublicKey(byte[] encoded, KeyPair localKeyPair)
            throws GeneralSecurityException {
        PublicKey publicKey = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(encoded));
        if (!(publicKey instanceof ECPublicKey)) {
            throw new GeneralSecurityException("La clave recibida no es una clave EC");
        }

        ECParameterSpec expected = ((ECPublicKey) localKeyPair.getPublic()).getParams();
        ECParameterSpec received = ((ECPublicKey) publicKey).getParams();
        if (!sameCurve(expected, received)) {
            throw new GeneralSecurityException("La clave recibida no usa la curva secp256r1");
        }
        return publicKey;
    }

    private static boolean sameCurve(ECParameterSpec left, ECParameterSpec right) {
        return left.getCurve().getField().getFieldSize() == right.getCurve().getField().getFieldSize()
                && left.getCurve().getA().equals(right.getCurve().getA())
                && left.getCurve().getB().equals(right.getCurve().getB())
                && left.getGenerator().equals(right.getGenerator())
                && left.getOrder().equals(right.getOrder())
                && left.getCofactor() == right.getCofactor();
    }

    private static void confirmKey(
            DataOutputStream output,
            DataInputStream input,
            byte[] confirmationKey,
            byte[] transcript,
            PeerRole localRole) throws IOException, GeneralSecurityException {
        byte[] localConfirmation = confirmationMac(confirmationKey, transcript, localRole);
        byte[] peerConfirmation = new byte[CONFIRMATION_BYTES];
        byte[] expected = confirmationMac(confirmationKey, transcript, localRole.opposite());
        try {
            output.write(localConfirmation);
            output.flush();
            input.readFully(peerConfirmation);
            if (!MessageDigest.isEqual(peerConfirmation, expected)) {
                throw new GeneralSecurityException("Fallo la confirmacion de la clave compartida");
            }
        } finally {
            Arrays.fill(localConfirmation, (byte) 0);
            Arrays.fill(peerConfirmation, (byte) 0);
            Arrays.fill(expected, (byte) 0);
        }
    }

    private static byte[] confirmationMac(
            byte[] confirmationKey, byte[] transcript, PeerRole role)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(confirmationKey, "HmacSHA256"));
        mac.update((byte) role.id());
        return mac.doFinal(transcript);
    }

    private static String createFingerprint(byte[] aesKeyBytes, byte[] transcriptHash)
            throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(FINGERPRINT_LABEL);
        digest.update(transcriptHash);
        byte[] hash = digest.digest(aesKeyBytes);
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            if (i > 0 && i % 2 == 0) {
                result.append('-');
            }
            result.append(String.format("%02X", hash[i]));
        }
        Arrays.fill(hash, (byte) 0);
        return result.toString();
    }

    private static byte[] nonceFor(PeerRole sender, long counter)
            throws GeneralSecurityException {
        if (counter < 0) {
            throw new GeneralSecurityException("Se agoto el espacio de nonces de la sesion");
        }
        ByteBuffer nonce = ByteBuffer.allocate(12);
        nonce.putInt(sender == PeerRole.SERVER ? 0x53324301 : 0x43325301);
        nonce.putLong(counter);
        return nonce.array();
    }

    private static byte[] aadFor(byte[] nonce) {
        ByteBuffer aad = ByteBuffer.allocate(1 + nonce.length);
        aad.put((byte) VERSION);
        aad.put(nonce);
        return aad.array();
    }

    private void incrementSendCounter() throws GeneralSecurityException {
        if (sendCounter == Long.MAX_VALUE) {
            throw new GeneralSecurityException("Se agoto el espacio de mensajes de la sesion");
        }
        sendCounter++;
    }

    private void incrementReceiveCounter() throws GeneralSecurityException {
        if (receiveCounter == Long.MAX_VALUE) {
            throw new GeneralSecurityException("Se agoto el espacio de mensajes de la sesion");
        }
        receiveCounter++;
    }

    private static void writeBlob(DataOutputStream output, byte[] data) throws IOException {
        output.writeInt(data.length);
        output.write(data);
    }

    private static byte[] readBlob(DataInputStream input, int maximum, String description)
            throws IOException {
        int length = input.readInt();
        if (length <= 0 || length > maximum) {
            throw new IOException("Longitud invalida para " + description + ": " + length);
        }
        byte[] data = new byte[length];
        input.readFully(data);
        return data;
    }

    private static String decodeUtf8(byte[] bytes) throws GeneralSecurityException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new GeneralSecurityException("El mensaje no contiene UTF-8 valido", e);
        }
    }

    private static byte[] concatenate(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    private static final class DecodedHello {
        private final PeerRole role;
        private final byte[] publicKey;

        private DecodedHello(PeerRole role, byte[] publicKey) {
            this.role = role;
            this.publicKey = publicKey;
        }
    }
}

