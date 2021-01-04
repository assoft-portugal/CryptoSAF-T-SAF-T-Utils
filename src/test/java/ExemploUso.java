package pt.cryptosaft.demo;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ExemploUso {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		byte[] input1 = "01".getBytes();
		byte[] input2 = "abcdefghijklmnop".getBytes();

		String keyB64 = "8/K97v8vQqbD/ShX5yx+3g==";
		String ivB64 = "+KSjwLJcoMXl7W+U1y5VtQ==";

		System.out.println("input1 : " + new String(input1));
		System.out.println("input2 : " + new String(input2));

		byte[] keyBytes = Base64.getDecoder().decode(keyB64);
		byte[] ivBytes = Base64.getDecoder().decode(ivB64);

		// Calculo dos dados cifrados usando a implementação do Java para comparação
		Cipher cypherJV = cipherInitializationJV(keyBytes, ivBytes);
		byte[] textCipherBytesJV = cypherJV.update(input1);
		System.out.println("[JV] input1:" + printHexBinary(textCipherBytesJV));

		textCipherBytesJV = cypherJV.update(input2);
		System.out.println("[JV] input2:" + printHexBinary(textCipherBytesJV));

		// Calculo dos dados cifrados usando a implementação AES Stream Cipher
		// Usa como base a implementação da cifra AES-ECB do BouncyCastle
		AESStreamCipher aesctr = new AESStreamCipher(Cipher.getInstance("AES/ECB/NoPadding", "BC"));

		SecretKey secKey = new SecretKeySpec(keyBytes, "AES");
		aesctr.init(false, secKey, ivBytes);

		byte[] input1CipherBytes = new byte[input1.length];

		aesctr.encrypt(input1, input1CipherBytes);

		System.out.println("[BC] input1:" + printHexBinary(input1CipherBytes));

		byte[] input2CipherBytes = new byte[input2.length];
		aesctr.encrypt(input2, input2CipherBytes);

		System.out.println("[BC] input2:" + printHexBinary(input2CipherBytes));

		aesctr.init(true, secKey, ivBytes);

		byte[] input1DecipherBytes = new byte[input1CipherBytes.length];
		aesctr.decrypt(input1CipherBytes, input1DecipherBytes);

		System.out.println("[BC] input1:" + new String(input1DecipherBytes));

		byte[] input2DecipherBytes = new byte[input2CipherBytes.length];
		aesctr.decrypt(input2CipherBytes, input2DecipherBytes);

		System.out.println("[BC] input2:" + new String(input2DecipherBytes));

	}

	// Só para efeitos de comparação.
	private static Cipher cipherInitializationJV(byte[] keyBytes, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException, IOException {
		Security.addProvider(new BouncyCastleProvider());

		SecretKey key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");

		IvParameterSpec paramSpec = new IvParameterSpec(iv);
		SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

		cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);

		return cipher;
	}
}
