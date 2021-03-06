package com.company;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.PropertyConfigurator;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.InputMismatchException;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author RAJAPAKSHA
 * @created 28/05/2021/ - 12:15 PM
 * @project Program Encrypt
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
        fileName[1] = "plainText.txt";
        fileName[2] = "EncryptText";

        //Read plainTextFile
        String plainText = readTextFile(fileName[1]);

        if (!plainText.equals("")) {
            if (isString(plainText)) {
                logger("Successful all plain text are alphabet characters and spaces.", 1);

                //Get the public key using keystore.jks filename
                PublicKey publicKey = getPublicKeyFromKeyStore(fileName[0]);
                if (publicKey != null) {
                    logger("Successful get public key.", 1);

                    //Encrypt the plain Text
                    Encrypt encrypt = new Encrypt();
                    String encryptText = encrypt.encrypt(plainText, publicKey);
                    if (!encryptText.equals("")) {

                        //Save Encrypted text to new file
                        if (saveEncryptTextFile(fileName[2], encryptText)) {
                            logger("Your Text File is Successfully Encrypted. Now Try to Run Decryption Program..!", 1);
                            logger("--------------- Thank You..! ---------------", 1);
                        } else {
                            logger("Can not save your encrypted file. Try again.", 3);
                        }
                    } else {
                        logger("Encrypting failure. Please try again.", 3);
                    }
                } else {
                    logger("Null public key found. Recheck your 'keystore.jks' file already exists. ", 3);
                }
            } else {
                logger("Please input only alphabet characters in 'plainText.txt file'. ", 3);
            }
        } else {
            logger("Please input only alphabet characters in 'plainText.txt file'. ", 3);
        }
    }

    //Read plain Text file
    private static String readTextFile(String fileName) {
        String plainText = "";
        try {
            File file = new File("../res/" + fileName);
            Scanner scanner = new Scanner(file);
            while (scanner.hasNextLine()) {
                plainText = scanner.nextLine();
            }
            logger("Successful read 'plainText.txt' file", 1);
            scanner.close();
        } catch (FileNotFoundException e) {
            logger("'plainText.txt' file not found in project location. " + e, 3);
        } catch (InputMismatchException e) {
            logger("Recheck the 'plainText.txt' file. " + e, 3);
        }
        return plainText;
    }

    //Check all characters are with space A-Z or a-z with regex
    private static boolean isString(String s) {
        Pattern p = Pattern.compile("^[ A-Za-z]+$");
        Matcher m = p.matcher(s);
        return m.matches();
    }

    //Get the public key from keystore file
    private static PublicKey getPublicKeyFromKeyStore(String keyFile) {
        //following comment is used to generate the keystore.jks file with my details.
        //keytool -genkeypair -alias induwara -storepass realrajapaksha -keypass realrajapaksha -keyalg RSA -keystore keystore.jks
        //You can change with your own details and after you must change below code.

        KeyStore keyStore = null;
        PublicKey publicKey = null;
        Certificate cert = null;
        InputStream ins = null;

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

            try {
                //'induwara' is -alias in above keystore file generate code
                cert = keyStore.getCertificate("induwara");
                logger("Successful get keystore certificate.", 1);
            } catch (KeyStoreException e) {
                logger("Key Store can not get certificate. try again. " + e, 3);
            }

            try {
                publicKey = cert.getPublicKey();
                logger("Successful get certificate public key.", 1);
            } catch (NullPointerException e) {
                logger("can't get the certificate public key. " + e, 3);
            }
        } else {
            logger("'keystore.jks' not found. Try again. Recheck your 'keystore.jks' file already exists", 3);
        }

        return publicKey;
    }

    //Save all encrypted characters to file
    private static boolean saveEncryptTextFile(String fileName, String encryptText) {
        try {
            FileWriter fileWriter = new FileWriter("../res/" + fileName);
            fileWriter.write(encryptText);
            fileWriter.close();
            logger("Successful saved encrypt text '" + fileName + "'", 1);
            return true;
        } catch (IOException e) {
            logger("'" + fileName + "' not found. Try again." + e, 3);
            return false;
        }
    }
}
