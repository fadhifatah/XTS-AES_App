package core;


public class XTS {
    private static final int KEY_SIZE = 256;
    private static final int SPLIT_KEY_SIZE = 128;
    private static final int BYTE_SIZE = 8;
    private static final int BLOCK_SIZE = 128;

    private int[] key1;
    private int[] key2;
    private AES aes1;
    private AES aes2;

    public XTS() {
        this.key1 = new int[SPLIT_KEY_SIZE / BYTE_SIZE];
        this.key2 = new int[SPLIT_KEY_SIZE / BYTE_SIZE];

        this.aes1 = new AES();
        this.aes2 = new AES();
    }

    public int[] encrpyt(int[] key, int[] plainText) throws Exception{
        // set-up needed keys
        if (key.length != KEY_SIZE / BYTE_SIZE)
            throw new Exception("Size of key is must be 256 bits!");

        System.arraycopy(key, 0, key1, 0, key.length);
        System.arraycopy(key, SPLIT_KEY_SIZE / BYTE_SIZE, key2, 0, key.length);

        aes1.setKey(Util.int2byte(key1));
        aes2.setKey(Util.int2byte(key2));

        // initiate return cipher-text object
        int[] cipherText = new int[plainText.length];

        int blockIteration = plainText.length / (BLOCK_SIZE / BYTE_SIZE);
        int[] plainTextPerBlock = new int[BLOCK_SIZE / BYTE_SIZE];
        int[] cipherTextPerBlock;

        // begin encryption
        for (int i = 0; i < blockIteration - 1; i++) {
            System.arraycopy(plainText, i * 16, plainTextPerBlock, 0, plainTextPerBlock.length);
            cipherTextPerBlock = blockEncryption(plainTextPerBlock, i);
        }

        return cipherText;
    }

    private int[] blockEncryption(int[] plainTextPerBlock, int i) {
        return null;
    }
}
