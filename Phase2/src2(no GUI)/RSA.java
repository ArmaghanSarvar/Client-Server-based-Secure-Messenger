import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSA {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
//        System.out.println(pair.getPrivate().getClass());
//        System.out.println(pair.getPublic());
        return pair;
    }

    public static String encryptSig(String plainText, PrivateKey privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decryptSig(String cipherText, PublicKey publicKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }


    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }


    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static PublicKey StringToPubKey(String pubStr){
        //converting string to Bytes
        byte[] byte_pubkey;
        PublicKey public_key = null;
        byte_pubkey  = Base64.getDecoder().decode(pubStr);

        //converting it back to public key
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
            public_key = (PublicKey) factory.generatePublic(new X509EncodedKeySpec(byte_pubkey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return public_key;
    }

    public static PrivateKey StringToPriKey(String pubStr) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] byte_prikey;
        PrivateKey privateKey = null;
        byte_prikey  = Base64.getDecoder().decode(pubStr);

        // extract the private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(byte_prikey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        privateKey = kf.generatePrivate(keySpec);
        //converting it back to public key
        return privateKey;
    }



    public static void main(String[] args) throws Exception {
        // First generate a public/private key pair
        KeyPair pair = generateKeyPair();
        PrivateKey test = pair.getPrivate();

        // Our secret message
        String message = "the answer to life the universe and everything";
        String prrrr = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        PublicKey privKey = StringToPubKey(prrrr);
        // Encrypt the message
        String cipherText = encrypt(message, privKey);

         //Now decrypt it
        String decipheredMessage = decrypt(cipherText, pair.getPrivate());

        System.out.println(decipheredMessage);
    }
}
