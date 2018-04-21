package core;


public class XTS {
    private int[] key1;
    private int[] key2;
    private int[] alpha;
    private static AES aes1;
    private static AES aes2;

    public XTS() {
        this.key1 = new int[Util.SPLIT_KEY_SIZE / Util.BYTE_SIZE];
        this.key2 = new int[Util.SPLIT_KEY_SIZE / Util.BYTE_SIZE];
        this.alpha = new int[Util.SPLIT_KEY_SIZE / Util.BYTE_SIZE];

        this.alpha[this.alpha.length - 1] = Util.ALPHA;

        aes1 = new AES();
        aes2 = new AES();
    }

    /**
     * XTS encryption
     *
     * Original content from fushar
     * Modified by Fatah F
     *
     *
     * @param key
     * @param plainText
     * @return int[]
     * @throws Exception
     */
    public int[] encrpyt(int[] key, int[] plainText) throws Exception{
        // set-up needed keys
        if (key.length != Util.KEY_SIZE / Util.BYTE_SIZE)
            throw new Exception("Size of key is must be 256 bits!");

        System.arraycopy(key, 0, key1, 0, key1.length);
        System.arraycopy(key, Util.SPLIT_KEY_SIZE / Util.BYTE_SIZE, key2, 0, key2.length);

        aes1.setRoundKey(key1);
        aes2.setRoundKey(key2);

        // initiate return cipher-text object
        int[] cipherText = new int[plainText.length];

        int blockIteration = plainText.length / (Util.BLOCK_SIZE / Util.BYTE_SIZE);
        int[] plainTextPerBlock = new int[Util.BLOCK_SIZE / Util.BYTE_SIZE];
        int[] cipherTextPerBlock;

        // begin encryption
        for (int i = 0; i < blockIteration - 1; i++) {
            System.arraycopy(plainText, i * 16, plainTextPerBlock, 0, plainTextPerBlock.length);
            cipherTextPerBlock = blockEncryption(plainTextPerBlock, i);

            System.arraycopy(cipherTextPerBlock, 0, cipherText, i * 16, cipherTextPerBlock.length);
        }

        // handling for the last block
        if (plainText.length % (Util.BLOCK_SIZE / Util.BYTE_SIZE) == 0) {
            System.arraycopy(plainText, (blockIteration - 1) * 16, plainTextPerBlock, 0, plainTextPerBlock.length);
            cipherTextPerBlock = blockEncryption(plainTextPerBlock, blockIteration - 1);

            System.arraycopy(cipherTextPerBlock, 0, cipherText, (blockIteration - 1) * 16, cipherTextPerBlock.length);
        }
        // if the last block size isn't 128 bit then do stealing
        else {
            int lastBlockLength = plainText.length - (blockIteration * 16);
            int[] lastPlainTextBlock = new int[16];

            System.arraycopy(plainText, (blockIteration * 16), lastPlainTextBlock, 0, lastBlockLength);

            // stealing
            System.arraycopy(plainText, (blockIteration - 1) * 16, plainTextPerBlock,0, plainTextPerBlock.length);
            int[] cipherTextBlockNmin1 = blockEncryption(plainTextPerBlock, blockIteration - 1);

            System.arraycopy(cipherTextBlockNmin1, 0, cipherText, blockIteration * 16, lastBlockLength);

            System.arraycopy(cipherTextBlockNmin1, lastBlockLength, lastPlainTextBlock, lastBlockLength, lastPlainTextBlock.length - lastBlockLength);
            cipherTextPerBlock = blockEncryption(lastPlainTextBlock, blockIteration);

            System.arraycopy(cipherTextPerBlock, 0, cipherText, (blockIteration - 1) * 16, cipherTextPerBlock.length);
        }

        return cipherText;
    }

    /**
     * XTS encryption per block
     *
     * Original content from fushar
     * Modified by Fatah F
     *
     * @param plainTextPerBlock
     * @param blockIndex
     * @return
     */
    private int[] blockEncryption(int[] plainTextPerBlock, int blockIndex) {
        int[] firstAESEncryption = aes2.encrypt(Util.TWEAK);

        int[] tmp = this.alpha;
        for (int i = 0; i < blockIndex - 1; i++) {
            assert tmp != null;
            tmp = Util.multiplyGF2_128(tmp, this.alpha);
        }

        int[] tmp2 = Util.multiplyGF2_128(firstAESEncryption, tmp);

        int[] tmp3 = new int[Util.BLOCK_SIZE / Util.BYTE_SIZE];
        for (int j = 0; j < tmp3.length; j++) {
            assert tmp2 != null;
            tmp3[j] = plainTextPerBlock[j] ^ tmp2[j];
        }

        int[] secondAESEncryption = aes1.encrypt(tmp3);

        int[] result = new int[Util.BLOCK_SIZE / Util.BYTE_SIZE];
        for (int k = 0; k < result.length; k++)
            result[k] = secondAESEncryption[k] ^ tmp2[k];

        return result;
    }

    /**
     * XTS decryption
     *
     * Original content from fushar
     * Modified by Aldi P
     *
     * @param key
     * @param cipherText
     * @return
     * @throws Exception
     */
    public int[] decrypt(int[] key, int[] cipherText) throws Exception {
    	// set-up needed keys
        if (key.length != Util.KEY_SIZE / Util.BYTE_SIZE)
            throw new Exception("Size of key is must be 256 bits!");

        System.arraycopy(key, 0, key1, 0, key1.length);
        System.arraycopy(key, Util.SPLIT_KEY_SIZE / Util.BYTE_SIZE, key2, 0, key2.length);

        aes1.setRoundKey(key1);
        aes2.setRoundKey(key2);
        
        //initiate return plain-text object
        int[] plainText = new int[cipherText.length];
        
        int blockIteration = cipherText.length / (Util.BLOCK_SIZE / Util.BYTE_SIZE);
        int[] cipherTextPerBlock = new int[Util.BLOCK_SIZE / Util.BYTE_SIZE];
        int[] plainTextPerBlock;
        
        //begin decryption
        for (int i = 0; i < blockIteration - 1; i++) {
        	System.arraycopy(cipherText, i * 16, cipherTextPerBlock, 0, cipherTextPerBlock.length);
        	plainTextPerBlock = blockDecryption(cipherTextPerBlock, i);
        	
        	System.arraycopy(plainTextPerBlock, 0, plainText, i * 16, plainTextPerBlock.length);
        }
        
        // handling for the last block
        if (cipherText.length % (Util.BLOCK_SIZE / Util.BYTE_SIZE) == 0) {
        	System.arraycopy(cipherText, (blockIteration - 1) * 16, cipherTextPerBlock, 0, cipherTextPerBlock.length);
        	plainTextPerBlock = blockDecryption(cipherTextPerBlock, (blockIteration - 1));
        	
        	System.arraycopy(plainTextPerBlock, 0, plainText, (blockIteration - 1) * 16, plainTextPerBlock.length);
        }
        // if the last block size isn't 128 bit then do stealing
        else {
        	int lastBlockLength = cipherText.length - (blockIteration * 16);
        	int[] lastCipherTextBlock = new int[16];
        	
        	System.arraycopy(cipherText, (blockIteration * 16), lastCipherTextBlock, 0, lastBlockLength);
        	
        	//stealing
        	System.arraycopy(cipherText, (blockIteration - 1) * 16, cipherTextPerBlock, 0, cipherTextPerBlock.length);
        	int[] plainTextBlockNmin1 = blockDecryption(cipherTextPerBlock, blockIteration);
        	
        	System.arraycopy(plainTextBlockNmin1, 0, plainText, blockIteration * 16, lastBlockLength);
        	
        	System.arraycopy(plainTextBlockNmin1, lastBlockLength, lastCipherTextBlock, lastBlockLength, lastCipherTextBlock.length - lastBlockLength);
        	plainTextPerBlock = blockDecryption(lastCipherTextBlock, blockIteration - 1);
        	
        	System.arraycopy(plainTextPerBlock, 0, plainText, (blockIteration - 1) * 16, plainTextPerBlock.length);
        }

    	return plainText;
    }

    /**
     * XTS decryption per block
     *
     * Original content from fushar
     * Modified by Aldi P
     *
     * @param cipherTextPerBlock
     * @param blockIndex
     * @return
     */
    private int[] blockDecryption(int[] cipherTextPerBlock, int blockIndex) {
    	int[] firstAESDecryption = aes2.encrypt(Util.TWEAK);
    	
    	int[] tmp = this.alpha;
    	for (int i = 0; i < blockIndex - 1; i++) {
            assert tmp != null;
            tmp = Util.multiplyGF2_128(tmp, this.alpha);
    	}
    	
    	int[] alpha2 = tmp;
    	int[] tmp2 = Util.multiplyGF2_128(firstAESDecryption, alpha2);
    	
    	int[] tmp3 = new int[Util.BLOCK_SIZE / Util.BYTE_SIZE];
    	for (int j = 0; j < tmp3.length; j++) {
            assert tmp2 != null;
            tmp3[j] = cipherTextPerBlock[j] ^ tmp2[j];
    	}
    	
    	int[] secondAESDecryption = aes1.decrypt(tmp3);
    	
    	int[] result;
    	result = new int[Util.BLOCK_SIZE / Util.BYTE_SIZE];
    	for (int k = 0; k < result.length; k++) {
    		result[k] = secondAESDecryption[k] ^ tmp2[k];
    	}
    	
    	return result;
    }
}
