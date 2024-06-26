package dev.chaitanyaallu.telehealthserver.service;

import dev.chaitanyaallu.telehealthserver.commons.CryptoUtil;
import dev.chaitanyaallu.telehealthserver.commons.ECCKeyUtil;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class TelehealthServerService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Value("${client.url}")
    private String clientUrl;
    private KeyPair keyPair;
    private PrivateKey serverPrivateKey;
    private PublicKey serverPublicKey;
    private PublicKey clientPublicKey;
    private byte[] derivedKey; // Store the derived key

    private static final Logger logger = LoggerFactory.getLogger(TelehealthServerService.class);

    @PostConstruct
    public void init() throws Exception {
        logger.info("Initializing ECC key pair for the server.");
        // Generate the ECC key pair for the server
        this.keyPair = ECCKeyUtil.generateECCKeyPair();
        logger.info("Generated ECC key pair for the server");
        this.serverPrivateKey = keyPair.getPrivate();
        logger.info("Server private key: " + serverPrivateKey);
        this.serverPublicKey = keyPair.getPublic();
        logger.info("Server public key: " + serverPublicKey);
    }

    public void setClientPublicKey(String encodedClientPublicKey) throws Exception {
        logger.info("Setting client public key");
        this.clientPublicKey = ECCKeyUtil.decodePublicKey(encodedClientPublicKey);
        byte[] sharedSecret = ECCKeyUtil.generateSharedSecret(serverPrivateKey, clientPublicKey);
        this.derivedKey = ECCKeyUtil.deriveKey(sharedSecret, 32); // For ChaCha20
    }

    public String getEncodedPublicKey() {
        return ECCKeyUtil.encodePublicKey(keyPair.getPublic());
    }

    public byte[] decryptData(byte[] encryptedData) throws Exception {
        if (this.derivedKey == null) {
            throw new IllegalStateException("Encryption key has not been set.");
        }

        // Splitting nonce and ciphertext correctly
        logger.info("Decrypting data using ChaCha20-Poly1305");
        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, 12); // First 12 bytes for nonce
        byte[] ciphertextAndMac = Arrays.copyOfRange(encryptedData, 12, encryptedData.length); // Rest for ciphertext + MAC

        ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        cipher.init(false, new ParametersWithIV(new KeyParameter(derivedKey), nonce));

        byte[] decryptedData = new byte[cipher.getOutputSize(ciphertextAndMac.length)];
        int len = cipher.processBytes(ciphertextAndMac, 0, ciphertextAndMac.length, decryptedData, 0);
        cipher.doFinal(decryptedData, len); // MAC check happens here

        // Assuming the last 32 bytes (if SHA3-256 was used) are the original hash
        logger.info("Verifying data integrity using SHA-3");
        int hashSize = 32; // Adjust based on the hash function used
        byte[] originalMessage = Arrays.copyOf(decryptedData, decryptedData.length - hashSize);
        byte[] originalHash = Arrays.copyOfRange(decryptedData, decryptedData.length - hashSize, decryptedData.length);

        // Verify the hash
        logger.info("Recalculating hash using SHA-3");
        byte[] recalculatedHash = CryptoUtil.hashUsingSHA3(originalMessage);
        if (!java.util.Arrays.equals(originalHash, recalculatedHash)) {
            throw new SecurityException("Data integrity check failed.");
        }

        return originalMessage;
    }

    public void decryptReceivedFile(Path encryptedFilePath) throws Exception {
        if (derivedKey == null) {
            throw new IllegalStateException("Encryption key has not been set.");
        }

        byte[] encryptedData = Files.readAllBytes(encryptedFilePath);

        // Extract nonce and decrypt
        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, 12);
        byte[] ciphertextAndMac = Arrays.copyOfRange(encryptedData, 12, encryptedData.length);
        byte[] decryptedData = CryptoUtil.decryptChaCha20(ciphertextAndMac, derivedKey, nonce);

        // Verify hash and extract original file content
        int hashSize = 32; // For SHA3-256
        byte[] originalFileBytes = Arrays.copyOfRange(decryptedData, 0, decryptedData.length - hashSize);
        byte[] originalHash = Arrays.copyOfRange(decryptedData, decryptedData.length - hashSize, decryptedData.length);
        byte[] recalculatedHash = CryptoUtil.hashUsingSHA3(originalFileBytes);
        if (!Arrays.equals(originalHash, recalculatedHash)) {
            throw new SecurityException("File integrity check failed.");
        }

        // Safer path manipulation
        Path decryptedFilePath = encryptedFilePath.getParent().resolve(encryptedFilePath.getFileName().toString().replaceAll("\\.enc$", ""));
        Files.write(decryptedFilePath, originalFileBytes);

    }

    public String encryptAndSendFile(Path filePath, String originalFilename) throws Exception {
        if (derivedKey == null) {
            throw new IllegalStateException("Encryption key has not been derived.");
        }

        // Read file bytes
        byte[] fileBytes = Files.readAllBytes(filePath);

        // Hash, Encrypt, Combine with nonce
        byte[] messageHash = CryptoUtil.hashUsingSHA3(fileBytes);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(fileBytes);
        outputStream.write(messageHash);
        byte[] combinedMessage = outputStream.toByteArray();

        byte[] nonce = CryptoUtil.generateNonce();
        byte[] encryptedMessage = CryptoUtil.encryptChaCha20(combinedMessage, derivedKey, nonce);
        byte[] combinedEncryptedMessage = CryptoUtil.combineNonceAndCiphertext(nonce, encryptedMessage);

        // Temporarily write to a file (if needed)
        Path encryptedFilePath = Files.createTempFile(null, ".enc");
        Files.write(encryptedFilePath, combinedEncryptedMessage);

        // Prepare and send the encrypted file
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new FileSystemResource(encryptedFilePath.toFile()));
        body.add("originalFilename", originalFilename); // Include original filename as form data

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(clientUrl+"/receiveFile", requestEntity, String.class);

        // Check response status and handle errors
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to send file: " + response.getBody());
        }

        // Optionally, delete the temporary file after sending
        Files.delete(encryptedFilePath);

        // Return response body or handle as needed
        return response.getBody();
    }



    public String encryptAndSend(String message) {
        try {
            // Ensure derivedKey has been generated
            logger.debug("Encrypting message using derived key and sending to client");
            if (derivedKey == null) {
                throw new IllegalStateException("Encryption key has not been derived.");
            }

            // Hash the message using SHA-3
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] messageHash = CryptoUtil.hashUsingSHA3(messageBytes);

            logger.info("Hashing message using SHA-3");
            // Combine the message and its hash
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(messageBytes);
            outputStream.write(messageHash);
            byte[] combinedMessage = outputStream.toByteArray();

            // Encrypt the combined message
            logger.info("Encrypting the combined message using ChaCha20-Poly1305");
            byte[] nonce = CryptoUtil.generateNonce();
            byte[] encryptedMessage = CryptoUtil.encryptChaCha20(combinedMessage, derivedKey, nonce);
            byte[] combinedEncryptedMessage = CryptoUtil.combineNonceAndCiphertext(nonce, encryptedMessage);
            String encodedMessage = Base64.getEncoder().encodeToString(combinedEncryptedMessage);

            // Send the encrypted message to the client
            logger.info("Sending encrypted message to client");
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            HttpEntity<String> request = new HttpEntity<>(encodedMessage, headers);

            System.out.println("Sending encrypted message: " + encodedMessage);

            ResponseEntity<String> response = restTemplate.postForEntity(clientUrl + "/receiveEncryptedMessage", request, String.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Failed to send encrypted message. Status: " + response.getStatusCode());
            }

            return response.getBody();
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
