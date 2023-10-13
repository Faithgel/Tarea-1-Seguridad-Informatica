import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryptor {

    public static void main(String[] args) {
        try {
            File keyStoreFile = new File("KeyStore.jks");
            File inFile = new File("mensaje_cifrado.txt");
            File outFile = new File("salida.txt");
            String password = "store1234";

            PublicKey publicKey = getPublicKeyFromCertificate("certFelipeCS.cer");
            PrivateKey privateKey = getPrivateKeyFromKeyStore(keyStoreFile, password);

            byte[] iv, secretKey, firma, mensaje;

            try (FileInputStream fileInputStream = new FileInputStream(inFile)) {
                iv = readBytesFromFile(fileInputStream, 16);
                secretKey = readBytesFromFile(fileInputStream, 256);
                firma = readBytesFromFile(fileInputStream, 256);
                mensaje = readRemainingBytes(fileInputStream);
            }

            SecretKey sessionKey = decryptAESKey(secretKey, privateKey);

            byte[] decryptedMessage = decryptFile(mensaje, sessionKey, iv);
            byte[] hash = calculateHash(decryptedMessage);

            compararHash(firma, publicKey, hash);

            try (FileOutputStream fileOutputStream = new FileOutputStream(outFile)) {
                fileOutputStream.write(decryptedMessage);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void compararHash(byte[] firma, PublicKey publicKey, byte[] mensaje) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        signature.update(mensaje);

        if (signature.verify(firma)) {
            System.out.println("Firma digital válida. El mensaje es auténtico.");
        } else {
            System.out.println("Firma digital no válida. El mensaje podría haber sido alterado.");
        }
    }

    public static byte[] decryptFile(byte[] mensaje, SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(mensaje);
    }

    public static SecretKey decryptAESKey(byte[] secretKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] keyData = cipher.doFinal(secretKey);
        return new SecretKeySpec(keyData, 0, keyData.length, "AES");
    }

    public static PublicKey getPublicKeyFromCertificate(String certificateFile) throws Exception {
        FileInputStream fis = new FileInputStream(certificateFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(fis);
        return x509Certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyStore(File keyStoreFile, String password) throws Exception {
        KeyStore myKeyStore = KeyStore.getInstance("JKS");
        try (FileInputStream inStream = new FileInputStream(keyStoreFile)) {
            myKeyStore.load(inStream, password.toCharArray());
            return (PrivateKey) myKeyStore.getKey("mykey", password.toCharArray());
        }
    }

    public static byte[] readBytesFromFile(FileInputStream fileInputStream, int length) throws IOException {
        byte[] data = new byte[length];
        fileInputStream.read(data);
        return data;
    }

    public static byte[] readRemainingBytes(FileInputStream fileInputStream) throws IOException {
        int remainingBytes = fileInputStream.available();
        byte[] data = new byte[remainingBytes];
        fileInputStream.read(data);
        return data;
    }

    public static byte[] calculateHash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(data);
        return md.digest();
    }
}
