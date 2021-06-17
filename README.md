# RSA Encrypt and Decrypt
[![release][0]][1]

This is a simple text file encrypt and decrypt program with an RSA algorithm. This will help you how to work the RSA algorithm to encrypt and decrypt text files using the public key and private key.

## Run the Program

Just need to these are on your computer.
- Windows computer (log file in ``C:\\encrypt decrypt\\``).
- java JDK 1.8.0_261.
- java compilling IDE (Intellij IDEA).

### Step 1

- Download [release v1.0][1].
- Extract the zip file.
- Open **Program Encrypt** and **Program Decrypt** in separately two projects.
- Build two programs once.


### Step 2

- Open **res** folder.
- Create a ``plainText.txt`` file with your text.
- Open the command prompt in the res folder.
- Type the following command to create keystore.jks :

```keytool -genkeypair -alias induwara -storepass realrajapaksha -keypass realrajapaksha -keyalg RSA -keystore keystore.jks```


### Step 3
- Run once **Program Encrypt** project.
- After running it, you can see EncryptText in the res folder.
- Then need to run once **Program Decrypt** project.
- Finally, you can see the ``rePlainText.txt`` file with your text.
- Also logs of running program saved in ``C:\\encrypt decrypt\\`` folder.

## About Project
Program Encrypt project run, check and read the 'plainText.txt' file and get only Strings. after that, check the valid 'keystore.jks' and read the public key. Then encrypt the plainText using the public key. Finally, encrypt text save to 'EncryptText' file.

Program Decrypt project run, check and read the 'EncryptText' file and get the characters. After that get and validate the private key. Then EncryptText file's characters are decrypted to plainText using that private key. Finally, decrypt text save to 'rePlainText.txt' file.

## Summary
RSA is a public-key cryptosystem that is widely used for secure data transmission. You can simulate how it works. We can get separate error logs after damage keystore.jks or EncryptText file. So, we can assume to decrypt the encrypted text, just need to have a valid private key. 

[0]: https://img.shields.io/badge/release-v1.0-green
[1]: https://github.com/realrajapaksha/Encrypt-and-Decrypt/releases/tag/v1.0
