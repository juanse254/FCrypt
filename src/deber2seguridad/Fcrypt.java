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
    
    private SecretKey secretKey;
    private String secretKeyType;
    private Key pubKey =  null;
    private PrivateKey privKey =  null;
    private AsymmetricKeyParameter pubKeyExtern =  null;

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
                ArrayList Valores = FileCrypterD.Split(FileCrypterD.Read(args[3].trim())); // Values obtained from the cyphered file.
                boolean Existe = FileCrypterD.AsymmetricSignVerify((byte[]) Valores.get(0), (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decodeBase64(FileCrypterD.Read(args[2].trim()))), (byte[]) Valores.get(1)); //Verifiy if the signature is right or quits.
                if (!Existe) {
                    System.err.print("Firma Invalida.");
                    break;
                }
                byte[] Llave_asimetrica_des = FileCrypterD.AsymmetricDecryption((AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.decodeBase64(FileCrypterD.Read(args[1].trim()))), (byte[]) Valores.get(1));//decrypts symetric key using the asymetric keys.
                SecretKey clave = new SecretKeySpec(Llave_asimetrica_des, "AES"); //Creates symetric key from bytes.
                byte[] Datos_des = FileCrypterD.SymmetricDecryption((byte[]) Valores.get(2), clave); // Decrypts the file with the keys.
                FileCrypterD.Write(args[4].trim(), Datos_des); // writes the decrypted message to the file.
                break;
            case "-e": // Encryption
                byte[] Dato_Encriptado = FileCrypterD.SymmetricEncryption(FileCrypterD.Read(args[3].trim())); //Cipher the message
                FileCrypterD.GenerateRSA("Public_Key", args[2].trim()); //Generate public and private keys as wwell as the symetric key.
                FileCrypterD.pubKeyExtern = (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decodeBase64(FileCrypterD.Read(args[1].trim()))); // Reads public key from remitent.
                byte[] Pass_encriptado = FileCrypterD.AsymmetricEncryption(FileCrypterD.pubKeyExtern, FileCrypterD.secretKey.getEncoded()); // crypts the symetric key asymetrically.
                byte[] Pass_firmado = FileCrypterD.AsymmetricSign(FileCrypterD.privKey, Pass_encriptado); // generates signature for the asymetric key.
                FileCrypterD.Write(args[4].trim(), FileCrypterD.Join(Dato_Encriptado, Pass_encriptado, Pass_firmado)); // Merges the key and the message together.
                break;
            case "-g": // Generates secret of keys and cypher protocol.
                FileCrypterD.GenerateRSA("Public_Key", "Private_key");
            default:
                System.err.println("Error en la opcion, ingrese -d o -e.");
                break;
        }

    }

    /*
    Generates the RSA keypairs and saves to path.
    Atirbutes KeyFileName or path, PrivateKeyName or path
    Returns Null
    */    
    private void GenerateRSA(String publicKeyFilename, String privateFilename) {

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC"); // Algorithm RSA from Bouncy Castle
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG"); // Random from  SHA1 PRNG
            generator.initialize(2048, random); // key of 2048 bits

            KeyPair pair = generator.generateKeyPair();
            this.pubKey = pair.getPublic();
            this.privKey = pair.getPrivate();

            this.Write(privateFilename, Base64.encodeBase64(this.privKey.getEncoded())); //write keys
            this.Write(publicKeyFilename, Base64.encodeBase64(this.pubKey.getEncoded()));

        } catch (Exception e) {
            System.out.println(e);
        }
    }

    /*
    Crypts Symetrically the passed data.
    Atirbutes Data to be crypted symetrically
    Returns byte[] Array of crypted bytes.
    */   
    private byte[] SymmetricEncryption(byte[] Datos) throws NoSuchAlgorithmException, NoSuchPaddingException, DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedEncodingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); //Algorithm AES
        keyGen.init(128); // key of 128 bits
        secretKey = keyGen.generateKey();
        secretKeyType = secretKey.getFormat();
        Cipher encryptCipher = Cipher.getInstance("AES"); //encrypt symetrically.
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encByte = encryptCipher.doFinal(Datos);
        return encByte;
    }

    /*
    Decrypts Symetrically using the provided secret key
    Atirbutes data to be decrypted, secret key for decryption
    Returns bytes[] of decrypted data
    */   
    private byte[] SymmetricDecryption(byte[] Datos_cif, SecretKey key) throws DataLengthException, IllegalStateException, InvalidCipherTextException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("AES"); //decrypt symetrically with AES
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] ByteDec = decryptCipher.doFinal(Datos_cif);
        return ByteDec;
    }

    /*
    Crypts Asymetrically the passed data.
    Atirbutes Public key to be used , password used as salt.
    Returns EncodedCipher a byte of arrays of the coded blocks in RSA.
    */  
    private byte[] AsymmetricEncryption(AsymmetricKeyParameter Publica, byte[] password) throws InvalidCipherTextException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        AsymmetricBlockCipher Cipher = new RSAEngine(); //Crypt with RSA engine.
        Cipher = new org.bouncycastle.crypto.encodings.PKCS1Encoding(Cipher); // Encoding PKCS1.
        Cipher.init(true, Publica);
        byte[] EncodedCipher = Cipher.processBlock(password, 0, password.length); //Process per block.
        return EncodedCipher;
    }

    /*
    Decrypts Asymetrically the passed data.
    Atirbutes Private key to be used , password used as desalter.
    Returns DecodedCypher a byte of arrays of the decoded blocks in RSA.
    */
    private byte[] AsymmetricDecryption(AsymmetricKeyParameter Privada, byte[] password) throws InvalidCipherTextException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        AsymmetricBlockCipher CipherOut = new RSAEngine();
        CipherOut = new org.bouncycastle.crypto.encodings.PKCS1Encoding(CipherOut);
        CipherOut.init(false, Privada);
        byte[] DecodedMes = password;
        byte[] DecodedCypher = CipherOut.processBlock(DecodedMes, 0, DecodedMes.length); //Decrypt per block.
        return DecodedCypher;
    }

    /*
    Signs Asymetrically the passed data.
    Atirbutes Private key to be used , password used as salt.
    Returns byte[] a byte of arrays of the signature generated for the file.
    */
    private byte[] AsymmetricSign(PrivateKey key, byte[] password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature signature = Signature.getInstance("SHA1withRSA", "BC"); //Sign with SHA1 in RSA
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG"); // Random SH1 PRNG
        signature.initSign(key, random);
        signature.update(password);
        byte[] signatureBytes = signature.sign(); //Generates Signature
        return signatureBytes;
    }

    /*
    Verifies the signature Asymetrically the passed data.
    Atirbutes byte[] array containing the signature, Public key to be used , password used as salt.
    Returns Boolean containing true or false depending on the status of the signature.
    */
    private boolean AsymmetricSignVerify(byte[] Sign, AsymmetricKeyParameter key, byte[] password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeySpecException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signature signature = Signature.getInstance("SHA1withRSA", "BC");
        RSAKeyParameters keys = (RSAKeyParameters) key;
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(keys.getModulus(), keys.getExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA"); //Creates public key.
        PublicKey rsaPub = kf.generatePublic(rsaSpec);
        signature.initVerify(rsaPub);
        signature.update(password);
        boolean Correct = signature.verify(Sign); //Verifies Signature.
        return Correct;
    }

    /*
    Reads a File
    Atirbutes name or path of file
    Returns array of strings of the file.
    */
    private byte[] Read(String FileName) throws IOException {
        File Archivo = new File(FileName); //Reads from file bytes.
        FileInputStream fis = null;
        byte[] Datos = null;
        try {
            fis = new FileInputStream(Archivo);
            Datos = IOUtils.toByteArray(fis);
            fis.close();
        } 
        catch (IOException e) {
            e.printStackTrace();
        }
        return Datos;
    }

    /*
    Writes a File
    Atirbutes name or path of file, byte array to be written.
    Returns void
    */
    private void Write(String FileName, byte[] datos) throws FileNotFoundException, IOException {
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(FileName)); //Writes from byte file.
        bos.write(datos);
        bos.flush();
        bos.close();
    }

    /*
    Merges blocks of code segmented by bytes.
    Atirbutes data to be merged, the asymetric block, the signature
    Returns array of byte with the merged blocks into an array.
    */
    private byte[] Join(byte[] Datos, byte[] Encriptado_asimetrico, byte[] Firma) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(); // Joins values in bytes and encodes to base64 to write to file.
        byte[] empty = new String("  ").getBytes(); //delimiter 
        outputStream.write(Base64.encodeBase64(Firma));
        outputStream.write(empty);
        outputStream.write(Base64.encodeBase64(Encriptado_asimetrico));
        outputStream.write(empty);
        outputStream.write(Base64.encodeBase64(Datos));
        byte[] total = outputStream.toByteArray();
        return total;
    }

    /*
    Splits blocks of code segmented by bytes.
    Atirbutes Data to be split and encoded.
    Returns Array with 3 sets of bytetypes, signature, key and encripted message.
    */
    private ArrayList Split(byte[] Encriptado) {
        String S = new String(Encriptado); // Creates three arrays delimited by "  "
        List<String> list = new ArrayList<String>(Arrays.asList(S.split("  ")));
        ArrayList Bytes = new ArrayList<>();
        for (String s : list) {
            Bytes.add(Base64.decodeBase64(s.getBytes()));
        }
        return Bytes; //Returns array with 3 sets of bytws signature, key and message.
    }

}
