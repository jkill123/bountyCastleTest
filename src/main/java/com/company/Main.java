package com.company;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws InvalidCipherTextException {
        String keyString = "mysecretkey12345";
        String input = "Мама мыла раму на даче летним жарким днем";
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];// Random vector
        random.nextBytes(iv);

//        String g = "GEOBf8n2tAUXXsTLrNF27+oEr2pRynbTEcAvsXaHbdQneVjrLs3FZxNsPcSGt16KirHEdddY1FvxAFBRrmb0uYfSQze4qWZzgvjxDec5380=";
//        String s = decrypt(keyString,g,xiv);

//        String of randomed vector
        String iv_64= Base64.getEncoder().encodeToString(iv);


        // TEST
        String in_64 = "dGsvJ2ZZr2poBheyNiqT6g==";//static vector fro testing
        String vv = "Люблю погулять у моря";

        String s1 = encript(keyString,vv,in_64);
        System.out.println(s1);
        String s2 = decrypt(keyString,s1,in_64);
        System.out.println(s2);
    }
    public static String encript(String keyString, String text, String iv_base64) throws InvalidCipherTextException {

        String keyStringBase64 = Base64.getEncoder().encodeToString(keyString.getBytes(StandardCharsets.UTF_8));
        byte [] inputBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] iv = Base64.getDecoder().decode(iv_base64.getBytes());

        //Set up
        AESEngine engine = new AESEngine();
        CBCBlockCipher blockCipher = new CBCBlockCipher(engine);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher, new PKCS7Padding());
        KeyParameter keyParam = new KeyParameter(Base64.getDecoder().decode(keyStringBase64));
        ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);

        // Encrypt
        cipher.init(true, keyParamWithIV);
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        int length = cipher.processBytes(inputBytes,0,inputBytes.length, outputBytes, 0);
        cipher.doFinal(outputBytes, length); //Do the final block
        String s = Base64.getEncoder().encodeToString(outputBytes);
        System.out.println("Encrypted String:"+s);

        return s;

    }
    public  static String decrypt(String keyString, String encryptedInput, String iv_base64 ) throws InvalidCipherTextException {

        // encode with padding
        //String encoded = Base64.getEncoder().withoutPadding().encodeToString(someByteArray);
        String keyStringBase64 = Base64.getEncoder().encodeToString(keyString.getBytes(StandardCharsets.UTF_8));
        byte [] inputBytes = encryptedInput.getBytes(StandardCharsets.UTF_8);
        byte[] iv = Base64.getDecoder().decode(iv_base64.getBytes());

        //Set up
        AESEngine engine = new AESEngine();
        CBCBlockCipher blockCipher = new CBCBlockCipher(engine);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher, new PKCS7Padding());
        KeyParameter keyParam = new KeyParameter(Base64.getDecoder().decode(keyStringBase64));
        ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);

        byte[] outputBytes = Base64.getDecoder().decode(encryptedInput);
        cipher.init(false, keyParamWithIV);
        byte[] comparisonBytes = new byte[cipher.getOutputSize(outputBytes.length)];
        int length = cipher.processBytes(outputBytes, 0, outputBytes.length, comparisonBytes, 0);
        cipher.doFinal(comparisonBytes, length); //Do the final block
        String s2 = new String(comparisonBytes);
        System.out.println("Decrypted String:"+s2);
        return s2;

    }
}
