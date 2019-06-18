package com.company;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;
import java.util.Random;

public class test {
    public static void main(String[] args) throws InvalidCipherTextException {
        String keyString = "mysecretkey12345";
        String input = "Мама мыла раму на даче летним жарким днем";
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        Random random = new Random();

        //Use for static vector
        // String xiv = "dGsvJ2ZZr2poBheyNiqT6g==";
        // byte[] iv = xiv.getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        int length;


        //Set up
        AESEngine engine = new AESEngine();
        CBCBlockCipher blockCipher = new CBCBlockCipher(engine);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);
        KeyParameter keyParam = new KeyParameter(keyString.getBytes());
        ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);

        // Encrypt
        cipher.init(true, keyParamWithIV);
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        length = cipher.processBytes(inputBytes,0,inputBytes.length, outputBytes, 0);
        cipher.doFinal(outputBytes, length);
        String encryptedInput = new String(Base64.encode(outputBytes));
        System.out.println("Encrypted String:" +encryptedInput);

        //Decrypt

        cipher.init(false, keyParamWithIV);
        byte[] out2 = Base64.decode(encryptedInput);
        byte[] comparisonBytes = new byte[cipher.getOutputSize(out2.length)];
        length = cipher.processBytes(out2, 0, out2.length, comparisonBytes, 0);
        cipher.doFinal(comparisonBytes, length); //Do the final block
        String s2 = new String(comparisonBytes);
        System.out.println("Decrypted String:"+s2);

    }
}
