import java.security.KeyPair;

public class KeyExchang {
    
    private KeyPair keyPair;
    
    public KeyExchang() {
        try {
            keyPair = CryptoUtils.generateRSAKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public byte[] getPublicKey() {
        return keyPair.getPublic().getEncoded();
    }
    
    public byte[] decryptWithPrivateKey(byte[] encryptedData) {
        try {
            return CryptoUtils.decryptRSA(keyPair.getPrivate().getEncoded(), encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
