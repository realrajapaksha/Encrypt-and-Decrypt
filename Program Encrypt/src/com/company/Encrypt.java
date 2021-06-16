package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Encrypt extends MyLogger {

    public String encrypt(String plainText, PublicKey publicKey) {
        String cipherString = "";
        Cipher encryptCipher = null;
        byte[] cipherText = new byte[0];
        try {
            encryptCipher = Cipher.getInstance("RSA");
            logger("Successful get Instance.", 1);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger("Can not get Instance. Try again. ", 3);
        }

        try {
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            logger("Successful init with public key.", 1);
        } catch (InvalidKeyException e) {
            logger("Invalid public key. Try again. " + e, 3);
        }

        try {
            cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));
            logger("Successful get Bytes in encrypt cipher.", 1);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            logger("Can not get Bytes in encrypt cipher. Try again. " + e, 3);
        }

        cipherString = Base64.getEncoder().encodeToString(cipherText);
        return cipherString;
    }
}
