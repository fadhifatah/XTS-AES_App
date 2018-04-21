package test;

import core.Util;
import core.XTS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

public class TestMain {
    private static File input, key, output;

    public static void main(String[] args) throws Exception {
        XTS xts = new XTS();

        // simulation test for XTS encryption
        input = new File("C:\\Users\\Fatah\\Downloads\\Music\\idgaf.m4a");
        key = new File("C:\\Users\\Fatah\\IdeaProjects\\XTS-AES App\\src\\test\\key.xts");
        output = new File("C:\\Users\\Fatah\\IdeaProjects\\XTS-AES App\\src\\test\\output.xts");

        int[] plaintext = Util.file2int(input);
        System.out.println(plaintext.length);

        int[] keys = Util.key2int(key);
        System.out.println(keys.length);

        int[] ciphertext = xts.encrpyt(keys, plaintext);
        System.out.println(ciphertext.length);

        Util.int2file(ciphertext, output);
    }
}
