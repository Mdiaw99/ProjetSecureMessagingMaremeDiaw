
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
       //KeyPair keypair= keyPairGenerator.generateKeyPair();
       return keyPairGenerator.generateKeyPair();
    }

    public static void savePublicKey(PublicKey publicKey, String fileName) throws Exception {
        try (ObjectOutputStream publicKeyStream = new ObjectOutputStream(new FileOutputStream(fileName))) {
            publicKeyStream.writeObject(publicKey);
        }
    }

    public static void savePrivateKey(PrivateKey privateKey, String fileName) throws Exception {
        try (ObjectOutputStream privateKeyStream = new ObjectOutputStream(new FileOutputStream(fileName))) {
            privateKeyStream.writeObject(privateKey);
        }
    }

    public static byte[] encryptRSA(byte[] publicKey, byte[] inputData) throws Exception {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(inputData);
    }

    public static byte[] decryptRSA(byte[] privateKey, byte[] inputData) throws Exception {
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(inputData);
    }

    // Signature d'un message avec la clé privée
    public static byte[] sign(byte[] message, PrivateKey privateKey) throws Exception {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(privateKey); // initiation de la signature
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message);
        sign.update(hash);
        return sign.sign();
    }

    // Vérification de la signature avec la clé publique
    public static boolean verify(byte[] message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message);
        sign.update(hash);
        return sign.verify(signature);
    }
    // Générer un code d'authentification de message (MAC) 
    public static byte[] generateMAC(byte[] message, PrivateKey privateKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(privateKey.getEncoded(), "HmacSHA256"));
        return mac.doFinal(message);
    }

    // Vérifier un code d'authentification de message (MAC)
    public static boolean verifyMAC(byte[] message, byte[] mac, PublicKey publicKey) throws Exception {
        Mac verifier = Mac.getInstance("HmacSHA256");
        verifier.init(new SecretKeySpec(publicKey.getEncoded(), "HmacSHA256"));
        byte[] generatedMac = verifier.doFinal(message);
        return MessageDigest.isEqual(mac, generatedMac);
    }

    
}
