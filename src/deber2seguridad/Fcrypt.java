/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package deber2seguridad;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.apache.commons.io.IOUtils;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;



/**
 *
 * @author juanse254
 */
public class Fcrypt {
    
    SecretKey secretKey;
    String secretKeyType;
    String publicKeyFilename = null;
    String privateKeyFilename = null;
    Key pubKey =  null;
    PrivateKey privKey =  null;
    AsymmetricKeyParameter pubKeyExtern =  null;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, DataLengthException, InvalidCipherTextException, UnsupportedEncodingException, IllegalStateException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException, SignatureException, InvalidKeySpecException {

        Fcrypt FileCrypterD = new Fcrypt();

        if (args.length < 1) {
            System.err.println("Usage: java " + FileCrypterD.getClass().getName()
                    + "-e Recipient_Public_Key_Filename Generated_Private_Key_Filename Filename_to_Encript Encripted_Filename");
            System.err.println("Usage: java " + FileCrypterD.getClass().getName()
                    + "-d Generated_Private_Key_Filename Recipient_Public_Key_Filename  Encripted_Filename Decrypted_Filename");
            System.exit(1);
        }

        switch (args[0].trim()) {
            case "-d": // Decription
                ArrayList Valores = FileCrypterD.Split(FileCrypterD.Read(args[3].trim())); // Valores Obtenidos de archivo encriptado.
                Boolean Existe = FileCrypterD.AsymmetricSignVerify((byte[]) Valores.get(0), (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decodeBase64(FileCrypterD.Read(args[2].trim()))), (byte[]) Valores.get(1)); //Verifica si la firma es correcta o termina.
                if (!Existe) {
                    System.err.print("Firma Invalida.");
                    break;
                }
                byte[] Llave_asimetrica_des = FileCrypterD.AsymmetricDecription((AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.decodeBase64(FileCrypterD.Read(args[1].trim()))), (byte[]) Valores.get(1));//Desencripta llave Simetrica encriptada asimetricamente.
                SecretKey clave = new SecretKeySpec(Llave_asimetrica_des, "AES"); //Crea la clave simetrica a partir de bytes.
                byte[] Datos_des = FileCrypterD.SymmetricDecription((byte[]) Valores.get(2), clave); // Desencripta el mensje con la llave simetrica.
                FileCrypterD.Write(args[4].trim(), Datos_des); // escribe el mensaje desencriptado al archivo.
                break;
            case "-e": // Encriptacion
                byte[] Dato_Encriptado = FileCrypterD.SymmetricEncription(FileCrypterD.Read(args[3].trim())); //Encripta Mensaje simetricamete.
                FileCrypterD.generateRSA("Public_Key", args[2].trim()); //Genera llaves publica y privada para encriptacion de llave siemtrica asimetricamente.
                FileCrypterD.pubKeyExtern = (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decodeBase64(FileCrypterD.Read(args[1].trim()))); // Lee llave publica del destinatario.
                byte[] Pass_encriptado = FileCrypterD.AsymmetricEncription(FileCrypterD.pubKeyExtern, FileCrypterD.secretKey.getEncoded()); // Encripta la llave simetrica asimetricamnte.
                byte[] Pass_firmado = FileCrypterD.AsymmetricSign(FileCrypterD.privKey, Pass_encriptado); // Genera Firma para llave simetrica encriptada.
                FileCrypterD.Write(args[4].trim(), FileCrypterD.Join(Dato_Encriptado, Pass_encriptado, Pass_firmado)); // Une la firma la llave encriptada y el mensaje encriptado.
                break;
            case "-g": // Generado secreto de llaves publica y privada
                FileCrypterD.generateRSA("Public_Key", "Private_key");
            default:
                System.err.println("Error en la opcion, ingrese -d o -e.");
                break;
        }

    }

    private void generateRSA(String publicKeyFilename, String privateFilename) {

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC"); // Algoritmo RSA de Bouncy Castle
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG"); // Aleatorio a partir de SHA1 PRNG
            generator.initialize(2048, random); // llave de 2048 bits

            KeyPair pair = generator.generateKeyPair();
            this.pubKey = pair.getPublic();
            this.privKey = pair.getPrivate();

            this.Write(privateFilename, Base64.encodeBase64(this.privKey.getEncoded())); //Escribe llaves
            this.Write(publicKeyFilename, Base64.encodeBase64(this.pubKey.getEncoded()));

        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private byte[] SymmetricEncription(byte[] Datos) throws NoSuchAlgorithmException, NoSuchPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedEncodingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); //Algoritmo AES
        keyGen.init(128); // llave de 128 bits
        secretKey = keyGen.generateKey();
        secretKeyType = secretKey.getFormat();
        Cipher encryptCipher = Cipher.getInstance("AES"); //Encriptacion simetrica.
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encByte = encryptCipher.doFinal(Datos);
        return encByte;
    }

    private byte[] SymmetricDecription(byte[] Datos_cif, SecretKey key) throws DataLengthException, IllegalStateException, InvalidCipherTextException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("AES"); //Desencriptacion Simetrica con AES
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] byteDec = decryptCipher.doFinal(Datos_cif);
        return byteDec;
    }

    private byte[] AsymmetricEncription(AsymmetricKeyParameter Publica, byte[] password) throws InvalidCipherTextException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        AsymmetricBlockCipher Cipher = new RSAEngine(); //Encriptacion con motor RSA.
        Cipher = new org.bouncycastle.crypto.encodings.PKCS1Encoding(Cipher); // Encoding PKCS1.
        Cipher.init(true, Publica);
        byte[] EncodedCipher = Cipher.processBlock(password, 0, password.length); //Procesamiento por bloques.
        return EncodedCipher;
    }

    private byte[] AsymmetricDecription(AsymmetricKeyParameter Privada, byte[] password) throws InvalidCipherTextException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        AsymmetricBlockCipher CipherOut = new RSAEngine();
        CipherOut = new org.bouncycastle.crypto.encodings.PKCS1Encoding(CipherOut);
        CipherOut.init(false, Privada);
        byte[] DecodedMes = password;
        byte[] DecodedCypher = CipherOut.processBlock(DecodedMes, 0, DecodedMes.length); //Desencriptamiento por bloques.
        return DecodedCypher;
    }

    private byte[] AsymmetricSign(PrivateKey key, byte[] password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature signature = Signature.getInstance("SHA1withRSA", "BC"); //Firma con SHA1 en RSA
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG"); // Aleatorio SH1 PRNG
        signature.initSign(key, random);
        signature.update(password);
        byte[] signatureBytes = signature.sign(); //Genera Firma
        return signatureBytes;
    }

    private boolean AsymmetricSignVerify(byte[] Sign, AsymmetricKeyParameter key, byte[] password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeySpecException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature signature = Signature.getInstance("SHA1withRSA", "BC");
        RSAKeyParameters keys = (RSAKeyParameters) key;
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(keys.getModulus(), keys.getExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA"); //Crea llave publica remitente.
        PublicKey rsaPub = kf.generatePublic(rsaSpec);
        signature.initVerify(rsaPub);
        signature.update(password);
        Boolean Correct = signature.verify(Sign); //Verifica firma.
        return Correct;
    }

    private byte[] Read(String FileName) throws IOException {
        File Archivo = new File(FileName); //Lee desde archivo bytes.
        FileInputStream fis = null;
        byte[] Datos = null;
        try {
            fis = new FileInputStream(Archivo);
            Datos = IOUtils.toByteArray(fis);
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Datos;
    }

    private void Write(String FileName, byte[] datos) throws FileNotFoundException, IOException {
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(FileName)); //Escribe desde archivo bytes.
        bos.write(datos);
        bos.flush();
        bos.close();
    }

    private byte[] Join(byte[] Datos, byte[] Encriptado_asimetrico, byte[] Firma) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(); // Une valores en bytes y los codifica en base64 para delimitacion en split.
        byte[] empty = new String("  ").getBytes(); //delimitador 
        outputStream.write(Base64.encodeBase64(Firma));
        outputStream.write(empty);
        outputStream.write(Base64.encodeBase64(Encriptado_asimetrico));
        outputStream.write(empty);
        outputStream.write(Base64.encodeBase64(Datos));
        byte[] total = outputStream.toByteArray();
        return total;
    }

    private ArrayList Split(byte[] Encriptado) {
        String S = new String(Encriptado); // Crea arreglo de byte[] con 3 arreglos delimitados por "  "
        List<String> list = new ArrayList<String>(Arrays.asList(S.split("  ")));
        ArrayList Bytes = new ArrayList<>();
        for (String s : list) {
            Bytes.add(Base64.decodeBase64(s.getBytes()));
        }
        return Bytes; //Devuelve el arreglo con los 3 arreglos de bytes , firma, llave, mensaje.
    }

}
