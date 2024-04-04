package dev.chaitanyaallu.telehealthserver.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import dev.chaitanyaallu.telehealthserver.service.TelehealthServerService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Logger;

@RestController
public class TelehealthServerController {

    @Autowired
    private TelehealthServerService cryptographyService;

    private Logger logger = Logger.getLogger(TelehealthServerController.class.getName());

    // In TelehealthServerController.java
    @PostMapping("/clientPublicKey")
    public ResponseEntity<?> setClientPublicKey(@RequestBody String encodedPublicKey) {
        try {
            logger.info("Received client public key");
            cryptographyService.setClientPublicKey(encodedPublicKey);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to set client public key");
        }
    }

    @GetMapping("/publicKey")
    public ResponseEntity<?> getServerPublicKey() {
        try {
            String encodedPublicKey = cryptographyService.getEncodedPublicKey();
            return ResponseEntity.ok(encodedPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to retrieve server public key");
        }
    }

    @PostMapping("/receiveFile")
    public ResponseEntity<String> receiveFile(@RequestParam("file") MultipartFile file, @RequestParam("originalFilename") String originalFilename) {
        String directoryPath = "received_files";
        Path directory = Paths.get(directoryPath);

        try {
            // Ensure the directory exists
            if (!Files.exists(directory)) {
                Files.createDirectories(directory); // Create the directory if it does not exist
            }

            // Save the encrypted file
            Path encryptedFilePath = directory.resolve(Objects.requireNonNull(originalFilename));
            file.transferTo(encryptedFilePath);

            // Decrypt the file
            Path decryptedFilePath = directory.resolve(originalFilename.replace(".enc", ""));
            cryptographyService.decryptReceivedFile(encryptedFilePath);

            // After decryption, handle the decrypted file as needed
            System.out.println("Decrypted file saved: " + decryptedFilePath);

            return ResponseEntity.ok("File received and decrypted successfully: " + decryptedFilePath);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Failed to receive and decrypt file: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Unexpected error during decryption: " + e.getMessage());
        }
    }

    @PostMapping("/uploadFile")
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            Path tempFile = Files.createTempFile(null, null);
            file.transferTo(tempFile.toFile());
            // Encrypt and send file
            String encryptedFilePath = cryptographyService.encryptAndSendFile(tempFile, file.getOriginalFilename());
            return ResponseEntity.ok().body("File encrypted and sent successfully: " + encryptedFilePath);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Failed to encrypt and send file: " + e.getMessage());
        }
    }


//    @PostMapping("/encrypt")
//    public byte[] encryptData(@RequestBody byte[] plaintext) {
//        try {
//            // Generate ECC key
//            byte[] key = cryptographyService.generateECCKey();
//
//            // Encrypt plaintext
//            return cryptographyService.encryptData(plaintext, key);
//        } catch (Exception e) {
//            e.printStackTrace();
//            return null;
//        }
//    }

//    @PostMapping("/decrypt")
//    public byte[] decryptData(@RequestBody byte[] encryptedData) {
//        try {
//            // Generate ECC key
//            byte[] key = cryptographyService.generateECCKey();
//
//            // Decrypt ciphertext
//            return cryptographyService.decryptData(encryptedData, key);
//        } catch (Exception e) {
//            e.printStackTrace();
//            return null;
//        }
//    }

    @PostMapping("/sendEncryptedMessage")
    public ResponseEntity<String> sendEncryptedMessageToClient(@RequestBody String message) {
        try {
            logger.info("Received request from user to send encrypted message to server");

            String encryptedMessage = cryptographyService.encryptAndSend(message);

            // Send the encrypted message to the client
            return ResponseEntity.ok(encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error sending encrypted message to client");
        }
    }

    @PostMapping("/receiveEncryptedMessage")
    public ResponseEntity<String> receiveEncryptedMessage(@RequestBody String encodedMessage) {
        try {

            System.out.println("Received encrypted message: " + encodedMessage);

            byte[] encryptedDataWithNonce = Base64.getDecoder().decode(encodedMessage);

            // Decrypt the data
            byte[] decryptedData = cryptographyService.decryptData(encryptedDataWithNonce);

            // Assuming the decrypted data is a UTF-8 encoded string
            String decryptedMessage = new String(decryptedData, StandardCharsets.UTF_8);
            System.out.println("Decrypted message: " + decryptedMessage);
            // Process the decrypted message as needed

            return ResponseEntity.ok().body("Message decrypted successfully: " + decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to process encrypted message");
        }
    }

}
