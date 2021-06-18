package com.company;

import org.apache.log4j.BasicConfigurator;

import org.apache.log4j.PropertyConfigurator;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.InputMismatchException;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author RAJAPAKSHA
 * @created 28/05/2021/ - 12:40 PM
 * @project Program Decrypt
 **/

public class Main extends MyLogger {

    public static void main(String[] args) {

        //Import and configure log4j Logger
        String log4jConfPath = "classes/log4j.properties";
        PropertyConfigurator.configure(log4jConfPath);
        BasicConfigurator.configure();

        //File names store in array
        String[] fileName = new String[3];
        fileName[0] = "keystore.jks";
        fileName[1] = "EncryptText";
        fileName[2] = "rePlainText.txt";

        //Read encryptText
        String encryptText = readEncryptFile(fileName[1]);

        if (!encryptText.equals("")) {

            //Get the private key using keystore.jks filename
            PrivateKey privateKey = getPrivateKeyFromKeyStore(fileName[0]);
            if (privateKey != null) {
                logger("Successful get private key.", 1);

                //Decrypt the encryptText
                Decrypt decrypt = new Decrypt();
                String rePlainText = decrypt.decrypt(encryptText, privateKey);
                if (!rePlainText.equals("")) {

                    //Save Encrypted text to new file
                    if (saveRePlainText(fileName[2], rePlainText)) {
                        logger("Encrypted Plain Text is: " + rePlainText, 1);
                        logger("Your Encrypted File is Successfully Decrypted and Saved.", 1);
                        logger("--------------- Thanks for Enjoy Decryption Program..! ---------------", 1);
                    } else {
                        logger("Can not save decrypted text file.", 3);
                    }
                } else {
                    logger("No text found this encrypt file.", 3);
                }
            } else {
                logger("Private Key is null. Please Check 'keystore.jks'.", 3);
            }
        } else {
            logger("'EncryptText' file have not any encrypted text. Please check and rerun program.", 3);
        }
    }

    //Read encryptText
    private static String readEncryptFile(String fileName) {
        String encryptText = "";
        try {
            File file = new File("../res/" + fileName);
            Scanner scanner = new Scanner(file);
            while (scanner.hasNextLine()) {
                encryptText = scanner.nextLine();
            }
            logger("Successful read 'EncryptText' file", 1);
            scanner.close();
        } catch (FileNotFoundException e) {
            logger("'EncryptText' file not found in project location. " + e, 3);
        } catch (InputMismatchException e) {
            logger("Recheck the 'EncryptText' file. " + e, 3);
        }
        return encryptText;
    }

    //Get the private key from keystore file
    public static PrivateKey getPrivateKeyFromKeyStore(String keyFile) {
        //following comment is used to generate the keystore.jks file with my details.
        //keytool -genkeypair -alias induwara -storepass realrajapaksha -keypass realrajapaksha -keyalg RSA -keystore keystore.jks
        //You can change with your own details and after you must change below code.

        KeyStore keyStore = null;
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        InputStream ins = null;
        PrivateKey privateKey = null;

        try {
            ins = new FileInputStream("../res/" + keyFile);
        } catch (FileNotFoundException e) {
            logger("'keystore.jks' not found. Try again. Recheck your 'keystore.jks' file already exists. " + e, 3);
        }

        if (ins != null) {
            try {
                keyStore = KeyStore.getInstance("JKS");
                logger("Successful get keystore instance.", 1);
            } catch (KeyStoreException e) {
                logger("keystore file must be the .jks file extension. " + e, 3);
            }

            try {
                //'realrajapaksha' is -storepass in above keystore file generate code
                keyStore.load(ins, "realrajapaksha".toCharArray());
                logger("Successful keystore load with password.", 1);
            } catch (IOException | NoSuchAlgorithmException | NullPointerException | CertificateException e) {
                logger("Key Store Load fail. Please check the 'keystore.jks' file. " + e, 3);
            }

            //'realrajapaksha' is -keypass in above keystore file generate code
            KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection("realrajapaksha".toCharArray());

            try {
                //'induwara' is -alias in above keystore file generate code
                privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("induwara", keyPassword);
            } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
                logger("Key Store file error. Please check file and rerun program.", 3);
            }

            try {
                privateKey = privateKeyEntry.getPrivateKey();
                logger("Successful get private key.", 1);
            } catch (NullPointerException e) {
                logger("can't get the private key. " + e, 3);
            }
        } else {
            logger("'keystore.jks' not found. Try again. Recheck your 'keystore.jks' file already exists", 3);
        }

        return privateKey;
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    //Save all encrypted characters to file
    private static boolean saveRePlainText(String fileName, String rePlainText) {
        try {
            FileWriter fileWriter = new FileWriter("../res/" + fileName);
            fileWriter.write(rePlainText);
            fileWriter.close();
            logger("Successful saved decrypted text '" + fileName + "'", 1);
            return true;
        } catch (IOException e) {
            logger("'" + fileName + "' not found. Try again." + e, 3);
            return false;
        }
    }
}
