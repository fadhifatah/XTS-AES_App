package test;

import core.Util;
import core.XTS;

import java.io.File;

/**
 * Test encryption and decryption function here.
 *
 * @author Fatah F
 */
public class TestMain {

    public static void main(String[] args) throws Exception {
        XTS xts = new XTS();

        // simulation test for XTS encryption
        File input = new File("C:\\Users\\Fatah\\IdeaProjects\\XTS-AES App\\src\\test\\output.xts");
        File key = new File("C:\\Users\\Fatah\\IdeaProjects\\XTS-AES App\\src\\test\\key.xts");
        File output = new File("C:\\Users\\Fatah\\IdeaProjects\\XTS-AES App\\src\\test\\result.xts");

        int[] plaintext = Util.file2int(input);
        System.out.println(plaintext.length);

        int[] keys = Util.key2int(key);
        System.out.println(keys.length);

        int[] ciphertext = xts.decrypt(keys, plaintext);
        System.out.println(ciphertext.length);

        Util.int2file(ciphertext, output);
    }
}
