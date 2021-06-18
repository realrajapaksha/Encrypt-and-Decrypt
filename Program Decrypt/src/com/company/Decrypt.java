package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author RAJAPAKSHA
 * @created 28/05/2021/ - 12:42 PM
 * @project Program Decrypt
 **/

public class Decrypt extends MyLogger {
    public String decrypt(String cipherText, PrivateKey privateKey) {
        Cipher decryptCipher = null;
        String decryptText = "";
        byte[] bytes = new byte[0];

        try {
            bytes = Base64.getDecoder().decode(cipherText);
        } catch (IllegalArgumentException e) {
            logger("'EncryptText' not have enough valid bits. Try again. " + e, 3);
        }

        try {
            decryptCipher = Cipher.getInstance("RSA");
            logger("Successful get Instance.", 1);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            logger("Can not get Instance. Try again. ", 3);
        }

        try {
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            logger("Successful init with private key.", 1);
        } catch (InvalidKeyException e) {
            logger("Invalid private key. Try again. " + e, 3);

        }
        try {
            decryptText = new String(decryptCipher.doFinal(bytes), UTF_8);
            logger("Successful get Bytes in decrypt cipher.", 1);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            logger("Can not get Bytes in decrypt cipher. Try again. " + e, 3);
        }
        return decryptText;
    }
}
