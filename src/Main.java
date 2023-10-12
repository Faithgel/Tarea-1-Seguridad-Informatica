/*
    Se necesita que usted intercambie, a través de email, un mensaje secreto con otro compañero del curso
(usted lo selecciona). Para ello debe crear un archivo de texto y cifrarlo con criptografía simétrica. La
llave secreta empleada debe ser incluida en el archivo de tal modo que su compañero sea el único
que pueda conocerla. Además, su mensaje debe incluir su firma digital (criptografía asimétrica), de
modo que su compañero pueda comprobar que usted creó el mensaje.
Basado en los códigos de programación usados en criptografía simétrica y de llave pública que están
disponibles en Moodle, se le pide:
1. Crear un par de llaves pública y privada del tipo RSA mediante la herramienta KeyTool.
Extraiga un certificado en formato X509 que contenga su llave pública y luego súbalo a
Moodle en el espacio que se defina para este fin.
2. Parte 1 - Usted debe desarrollar un programa en java que permita:
a. Generar una llave de sesión para encriptar un archivo de texto de largo arbitrario con
AES, cuyo contenido usted decide (es el que enviará a su compañero). UTILICE MODO
CBC. No se permite uso del modo EBC. Por lo tanto, deberá generar un vector de
inicialización (IV).
b. Generar Hash del Mensaje con SHA-1.
c. Encriptar (mediante RSA) llave de sesión con llave pública de su compañero. Como se
indicó esta llave pública debería estar en un certificado X509 y disponible en Moodle.
Si no, solicite a su compañero que envíe certificado al profesor.
d. Firme digitalmente el hash del mensaje. Utilice la KeyTool para acceder a su llave
privada.
Considere el siguiente orden estricto (por compatibilidad) de los datos escritos en el
archivo de salida:
• IV (en texto plano)
• ERSA(Ksesion, Kpublica_compañero)
• ERSA(Hash(Mensaje), Ksu_llave_privada)
• EAES(Mensaje, Ksesion)
 */

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Main {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, CertificateException {
        // Generar llave de sesion
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        Key key = keyGenerator.generateKey();

        // Generar IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        //Tomar mensaje de archivo
        FileInputStream fism = new FileInputStream("mensaje.txt");
        byte[] mensaje = new byte[fism.available()];
        fism.read(mensaje);
        fism.close();

        // Generar hash del mensaje
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] hash = messageDigest.digest(mensaje);

        // Encriptar llave de sesion con llave publica de compañero
        FileInputStream fileInputStream = new FileInputStream("certFelipeCS.cer");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        PublicKey publicKey = x509Certificate.getPublicKey();
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] llaveSesionEncriptada = new byte[0];
        try {
            llaveSesionEncriptada = cipher.doFinal(key.getEncoded());
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        // Firmar digitalmente hash del mensaje
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        FileInputStream keystorefis = new FileInputStream("KeyStore.jks");
        keyStore.load(keystorefis, "store1234".toCharArray());
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) keyStore.getKey("mykey", "store1234".toCharArray());
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        byte[] firma = signature.sign();

        // Encriptar mensaje con llave de sesion

        byte[] mensajeEncriptado;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            mensajeEncriptado = cipher.doFinal(mensaje);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        // Escribir en archivo
        FileOutputStream fileOutputStream = new FileOutputStream("mensaje-encriptado.txt");
        fileOutputStream.write(iv);
        fileOutputStream.write(llaveSesionEncriptada);
        fileOutputStream.write(firma);
        fileOutputStream.write(mensajeEncriptado);
        fileOutputStream.close();
    }
}
