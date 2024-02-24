import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class TestCrypto {
    public static void main(String[] args) throws Exception {
        try {
        // Simuler l'échange de clés
        KeyExchang alice = new KeyExchang();
        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        CryptoUtils.savePublicKey(keyPair.getPublic(), "public_key.txt"); //sauvegarde de la clé public dans un fichier
        CryptoUtils.savePrivateKey(keyPair.getPrivate(), "private_key.txt"); //sauvegarde de la clé privé dans la fichier

            // recuperer la clé public dépuis le fichier
            ObjectInputStream publicKeyStream = new ObjectInputStream(new FileInputStream("public_key.txt"));
             publicKey = (PublicKey) publicKeyStream.readObject();
            publicKeyStream.close();
            
            // recuperer la clé privé dépuis le fichier
            ObjectInputStream privateKeyStream = new ObjectInputStream(new FileInputStream("private_key.txt"));
            privateKey = (PrivateKey) privateKeyStream.readObject();
            privateKeyStream.close();

            // affichage des clés
            System.out.println("La Clé publique : " + publicKey);
            System.out.println("La Clé privée : " + privateKey);
        
        // alice envoie sa clé publique à bob
        byte[] alicePublicKey = alice.getPublicKey();
        
        // bob reçoit la clé publique d'alice et chiffre un message avec
        byte[] message = "Bonjour Alice!, voici mon message signé".getBytes(); // message a signer
       
        
            byte[] encryptedMessage = CryptoUtils.encryptRSA(alicePublicKey, message);
            
            byte[] signature = CryptoUtils.sign(message, privateKey); // bob signe le message
            System.out.println("Signature générée: " + Base64.getEncoder().encodeToString(signature));

            boolean verified = CryptoUtils.verify(message, signature, publicKey); //la signature est verifié
            System.out.println("La signature est vérifiée : " + verified);
            byte[] modifiedMessage = "Le message a été modifié.".getBytes();
            boolean isVerifiedModified = CryptoUtils.verify(modifiedMessage, signature, publicKey);
            System.out.println("La signature du message modifié est elle valide ? " + isVerifiedModified);

            byte[] mac = CryptoUtils.generateMAC(message, privateKey);
            System.out.println("MAC: " + mac);

            // Vérification du code d'authentification de message (MAC)
            boolean macVerified = CryptoUtils.verifyMAC(message, mac, publicKey);
            System.out.println("MAC vérifié : " + macVerified);
            
            // alice reçoit le message chiffré de bob et le déchiffre
            byte[] decryptedMessage = alice.decryptWithPrivateKey(encryptedMessage);
            System.out.println("Alice reçoit le message de bob: " + new String(decryptedMessage));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    
}
