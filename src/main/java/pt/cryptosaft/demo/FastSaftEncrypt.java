package pt.cryptosaft.demo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.codehaus.stax2.XMLInputFactory2;

public class FastSaftEncrypt {

	private static final String CIPHER_ALG = "AES/CTR/NoPadding";
	private static final String KEY_TYPE = "AES";
	private static final Charset CHARSET = StandardCharsets.ISO_8859_1;

	private static String input = null;
	private static String output = null;
	private static boolean cipherOper = true;
	private static String keyB64 = null;
	private static String ivB64 = null;

	private static HashSet<String> elementsToCypher = new HashSet<String>(Arrays.asList("AuditFile/Header/CompanyID/"));

	private static void printUsage() {
		System.out.println(
				"usage: java pt.cryptosaft.demo.FastSaftEncrypt <operation: E or D> <input xml file> <output xml file> <key in B64> <iv in B64>");
	}

	public static void main(String[] args) throws Exception {

		long start = System.currentTimeMillis();
		System.out.println("Start ");
		try {
			cipherOper = "E".equals(args[0]);

			System.out.println("Mode " + (cipherOper ? "ENCRYPT" : "DECRYPT"));

			input = args[1];
			output = args[2];

			System.out.println("Input File " + input);
			System.out.println("Output File " + output);

			keyB64 = args[3];
			ivB64 = args[4];

		} catch (ArrayIndexOutOfBoundsException aioobe) {
			printUsage();
			System.exit(0);
		}

		Cipher cipher = cipherInitialization();

		XMLInputFactory2 xmlif = staxFactoryInitialization(input);

		XMLStreamReader xmlr = null;

		try (InputStream targetStream = new FileInputStream(new File(input));
				Reader reader = readerInitialization(input, CHARSET);
				FileWriter writer = writerInitialization(output, CHARSET);) {

			xmlr = xmlif.createXMLStreamReader(targetStream);

			IterationParameters iParam = new IterationParameters();

			//
			// Parse the XML
			//

			while (xmlr.hasNext()) {
				iParam = processEvent(xmlr, reader, writer, cipher, iParam);
				xmlr.next();
			}

			writeToOutput(reader, writer);

			long duration = (System.currentTimeMillis() - start) / 1000;
			System.out.println("Done in " + duration + " seconds.");

		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		} finally {
			//
			// Close the reader
			//
			xmlr.close();
		}

	}

	private static IterationParameters processEvent(XMLStreamReader xmlr, Reader reader, FileWriter writer,
			Cipher cipher, IterationParameters iParam) throws IOException, XMLStreamException {

//		System.out.println("EVENT:[" + xmlr.getLocation().getLineNumber() + "][" + xmlr.getLocation().getColumnNumber()
//				+ "] " + xmlr.getEventType());
		try {
			switch (xmlr.getEventType()) {

			case XMLStreamConstants.START_ELEMENT:
				iParam.setNotCiphered(false);
				if (xmlr.hasName()) {

					/*
					 * System.out.println("\n\nSTART_ELEMENT=Line:" +
					 * xmlr.getLocation().getLineNumber() + ",Column:" +
					 * xmlr.getLocation().getColumnNumber() + ",Offset:" +
					 * xmlr.getLocation().getCharacterOffset() + " LocalName -> "+
					 * xmlr.getLocalName());
					 */
					iParam.getTree().add(xmlr.getLocalName());

					// System.out.println(iParam.getCurrentBranch());

					iParam.setElementToCipher(elementsToCypher.contains(iParam.getCurrentBranch()));

					iParam.setElementToCipher(true);

				}

				writeToOutput(xmlr, reader, writer, iParam);
				iParam.setStartElementOffset(xmlr.getLocation().getCharacterOffset());

				break;

			case XMLStreamConstants.CHARACTERS:

				if (xmlr.getTextCharacters().length > 0) {

					writeToOutput(xmlr, reader, writer, iParam);

					if (iParam.isElementToCipher()) {
						iParam.setValueStart(xmlr.getLocation().getCharacterOffset());
					}
				}
				break;

			case XMLStreamConstants.END_ELEMENT:
				if (iParam.isElementToCipher()) {

					// System.out.println("END_ELEMENT=Line:" + xmlr.getLocation().getLineNumber() +
					// ",Column:"
					// + xmlr.getLocation().getColumnNumber() + ",Offset:" +
					// xmlr.getLocation().getCharacterOffset()+ " LocalName -> "+
					// xmlr.getLocalName());

//				    System.out.println("branch: " + iParam.getCurrentBranch());

					iParam.setValueEnd(xmlr.getLocation().getCharacterOffset());

					if (iParam.getStartElementOffset() == xmlr.getLocation().getCharacterOffset()) {
						iParam.setValueStart(iParam.getPreviousElementEnd());
						iParam.setNotCiphered(true);
					}

					int realValueLenght = iParam.getValueLenght();
					if (realValueLenght != 0) {
						char[] cbuf = new char[realValueLenght];
						int len = reader.read(cbuf);

						String valueReal = new String(cbuf);
						if (!iParam.isNotCiphered()) {
							if (cipherOper) {
								valueReal = cipher(cipher, valueReal);
							} else {
								valueReal = decipher(cipher, valueReal);
							}
						}

						iParam.setNextOffset(iParam.getNextOffset() + realValueLenght);
						writer.write(valueReal);

					}

				}

				iParam.getTree().removeLast();
				iParam.setElementToCipher(false);
				iParam.setPreviousElementEnd(iParam.getNextOffset());

				break;

			default:
				// System.out.println("skip");

			}
		} catch (Exception e) {

			System.out.println("END_ELEMENT=Line:" + xmlr.getLocation().getLineNumber() + ",Column:"
					+ xmlr.getLocation().getColumnNumber() + ",Offset:" + xmlr.getLocation().getCharacterOffset());
			e.printStackTrace();
			System.exit(0);
		}
		return iParam;
	}

	private static FileWriter writerInitialization(String output, Charset charset) throws IOException {
		FileWriter writer = new FileWriter(new File(output), charset);
		return writer;
	}

	private static Reader readerInitialization(String input, Charset charset) throws FileNotFoundException {
		Reader reader = new BufferedReader(new InputStreamReader(new FileInputStream(new File(input)), charset));
		return reader;
	}

	private static XMLInputFactory2 staxFactoryInitialization(String input)
			throws FactoryConfigurationError, FileNotFoundException, XMLStreamException {
		//
		// Get an input factory
		//
		XMLInputFactory2 xmlif = (XMLInputFactory2) XMLInputFactory2.newInstance();

//		xmlif.setProperty(XMLInputFactory2.P_PRESERVE_LOCATION, Boolean.TRUE);

		xmlif.configureForConvenience();

		xmlif.setProperty(XMLInputFactory2.P_REPORT_PROLOG_WHITESPACE, Boolean.FALSE);

		return xmlif;
	}

	private static Cipher cipherInitialization() throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		// AES_CTR::
		byte[] keyBytes = Base64.getDecoder().decode(keyB64);
		SecretKey key = new SecretKeySpec(keyBytes, KEY_TYPE);
		Cipher cipher = Cipher.getInstance(CIPHER_ALG);
		byte[] iv = Base64.getDecoder().decode(ivB64);
		IvParameterSpec paramSpec = new IvParameterSpec(iv);
		SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), KEY_TYPE);

		int mode;
		if (cipherOper) {
			mode = Cipher.ENCRYPT_MODE;
		} else {
			mode = Cipher.DECRYPT_MODE;
		}

		cipher.init(mode, keySpec, paramSpec);
		return cipher;
	}

	private static void writeToOutput(XMLStreamReader xmlr, Reader reader, FileWriter writer,
			IterationParameters iParam) throws IOException {

		if ((xmlr.getLocation().getCharacterOffset() - iParam.getNextOffset()) > 0) {
			char[] cbuf;
			int len;

			cbuf = new char[xmlr.getLocation().getCharacterOffset() - iParam.getNextOffset()];

			len = reader.read(cbuf);

			// System.out.println("\nwrite-->" + new String(cbuf) + "<--\n");

			writer.write(cbuf, 0, len);

			iParam.setNextOffset(xmlr.getLocation().getCharacterOffset());
		}

	}

	private static void writeToOutput(Reader r, FileWriter w) throws IOException {
		char[] cbuf = new char[2048];
		int read;
		while ((read = r.read(cbuf)) != -1) {
			w.write(cbuf, 0, read);
		}
	}

	private static String cipher(Cipher cipher, String text) throws UnsupportedEncodingException {
		byte[] cipherTextBytes = cipher.update(text.getBytes(CHARSET));
		String cipherTextString = Base64.getEncoder().encodeToString(cipherTextBytes);
		return cipherTextString;
	}

	private static String decipher(Cipher cipher, String text) throws UnsupportedEncodingException {

		byte[] cipherTextBytes = Base64.getDecoder().decode(text);
		byte[] decipheredBytes = cipher.update(cipherTextBytes);
		String decipherTextString = new String(decipheredBytes, CHARSET);
		return decipherTextString;

	}

}