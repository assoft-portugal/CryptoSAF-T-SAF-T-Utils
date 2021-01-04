package pt.cryptosaft.demo;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

public class AESStreamCipher {

	final Cipher embeddedCipher;

	// the block size of the embedded block cipher
	final int blockSize;

	// the initialization vector
	byte[] iv;

	// current counter value
	final byte[] counter;

	// encrypted bytes of the previous counter value
	private final byte[] encryptedCounter;

	// number of bytes in encryptedCounter already used up
	private int used;

	// variables for save/restore calls
	private byte[] counterSave = null;
	private byte[] encryptedCounterSave = null;
	private int usedSave = 0;

	AESStreamCipher(Cipher cipher) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

		this.embeddedCipher = cipher;

		this.blockSize = cipher.getBlockSize();
		counter = new byte[blockSize];
		encryptedCounter = new byte[blockSize];
	}

	/**
	 * Resets the iv to its original value. This is used when doFinal is called in
	 * the Cipher class, so that the cipher can be reused (with its original iv).
	 */
	void reset() {
		System.arraycopy(iv, 0, counter, 0, blockSize);
		used = blockSize;
	}

	/**
	 * Save the current content of this cipher.
	 */
	void save() {
		if (counterSave == null) {
			counterSave = new byte[blockSize];
			encryptedCounterSave = new byte[blockSize];
		}
		System.arraycopy(counter, 0, counterSave, 0, blockSize);
		System.arraycopy(encryptedCounter, 0, encryptedCounterSave, 0, blockSize);
		usedSave = used;
	}

	/**
	 * Restores the content of this cipher to the previous saved one.
	 */
	void restore() {
		System.arraycopy(counterSave, 0, counter, 0, blockSize);
		System.arraycopy(encryptedCounterSave, 0, encryptedCounter, 0, blockSize);
		used = usedSave;
	}

	/**
	 * Initializes the cipher in the specified mode with the given key and iv.
	 *
	 * @param decrypting flag indicating encryption or decryption
	 * @param key        the key
	 * @param iv         the iv
	 *
	 * @exception InvalidKeyException if the given key is inappropriate for
	 *                                initializing this cipher
	 */
	void init(boolean decrypting, SecretKey key, byte[] iv) throws InvalidKeyException {
		if ((key == null) || (iv == null) || (iv.length != blockSize)) {
			throw new InvalidKeyException("Internal error");
		}

		this.iv = iv;
		reset();
		// always encrypt mode for embedded cipher
		embeddedCipher.init(Cipher.ENCRYPT_MODE, key);
	}

	/**
	 * Performs encryption operation.
	 *
	 * <p>
	 * The input plain text <code>plain</code>, starting at <code>plainOffset</code>
	 * and ending at <code>(plainOffset + len - 1)</code>, is encrypted. The result
	 * is stored in <code>cipher</code>, starting at <code>cipherOffset</code>.
	 *
	 * @param in  the buffer with the input data to be encrypted
	 * @param out the buffer for the result
	 * @return the length of the encrypted data
	 * @throws ShortBufferException
	 */
	int encrypt(byte[] in, byte[] out) throws ShortBufferException {
		return crypt(in, out);
	}

	// CTR encrypt and decrypt are identical
	int decrypt(byte[] in, byte[] out) throws ShortBufferException {
		return crypt(in, out);
	}

	/**
	 * Increment the counter value.
	 */
	private static void increment(byte[] b) {
		int n = b.length - 1;
		while ((n >= 0) && (++b[n] == 0)) {
			n--;
		}
	}

	/**
	 * Do the actual encryption/decryption operation. Essentially we XOR the input
	 * plaintext/ciphertext stream with a keystream generated by encrypting the
	 * counter values. Counter values are encrypted on demand.
	 * 
	 * @throws ShortBufferException
	 */
	private int crypt(byte[] in, byte[] out) throws ShortBufferException {
		if (in.length == 0) {
			return 0;
		}
		return implCrypt(in, out);
	}

	private int implCrypt(byte[] in, byte[] out) throws ShortBufferException {
		int len = in.length;
		int inOff = 0;
		int outOff = 0;
		int result = len;
		while (len-- > 0) {
			if (used >= blockSize) {
//            	System.out.println("         Counter:" + printHexBinary(counter));
				embeddedCipher.update(counter, 0, counter.length, encryptedCounter);
//              System.out.println("encryptedCounter:" + printHexBinary(encryptedCounter));
				increment(counter);
//              System.out.println("incrementCounter:" + printHexBinary(counter));
				used = 0;
			}
			out[outOff++] = (byte) (in[inOff++] ^ encryptedCounter[used++]);
		}
		return result;
	}

}
