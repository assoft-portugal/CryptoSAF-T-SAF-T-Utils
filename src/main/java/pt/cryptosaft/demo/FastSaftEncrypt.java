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
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.codehaus.stax2.XMLInputFactory2;

public class FastSaftEncrypt {

	// 
	// This algo is using the AES-ECB with a counter to implement AES-CTR. 
	// These two variables isn't used for now.
	//
	private static final String CIPHER_ALG = "AES/CTR/NoPadding";
	private static final String KEY_TYPE = "AES";
	private static Charset CHARSET = StandardCharsets.ISO_8859_1;

	private static String input = null;
	private static String output = null;
	private static boolean cipherOper = true;
	private static String keyB64 = null;
	private static String ivB64 = null;

	private static HashSet<String> elementsToCypher = new HashSet<String>(Arrays.asList(
			"AuditFile/MasterFiles/GeneralLedgerAccounts/Account/AccountDescription/",
			"AuditFile/MasterFiles/Customer/CustomerTaxID/", "AuditFile/MasterFiles/Customer/CompanyName/",
			"AuditFile/MasterFiles/Customer/Contact/", "AuditFile/MasterFiles/Customer/BillingAddress/BuildingNumber/",
			"AuditFile/MasterFiles/Customer/BillingAddress/StreetName/",
			"AuditFile/MasterFiles/Customer/BillingAddress/AddressDetail/",
			"AuditFile/MasterFiles/Customer/BillingAddress/City/",
			"AuditFile/MasterFiles/Customer/BillingAddress/PostalCode/",
			"AuditFile/MasterFiles/Customer/BillingAddress/Region/",
			"AuditFile/MasterFiles/Customer/BillingAddress/Country/",
			"AuditFile/MasterFiles/Customer/ShipToAddress/BuildingNumber/",
			"AuditFile/MasterFiles/Customer/ShipToAddress/StreetName/",
			"AuditFile/MasterFiles/Customer/ShipToAddress/AddressDetail/",
			"AuditFile/MasterFiles/Customer/ShipToAddress/City/",
			"AuditFile/MasterFiles/Customer/ShipToAddress/PostalCode/",
			"AuditFile/MasterFiles/Customer/ShipToAddress/Region/",
			"AuditFile/MasterFiles/Customer/ShipToAddress/Country/", "AuditFile/MasterFiles/Customer/Telephone/",
			"AuditFile/MasterFiles/Customer/Fax/", "AuditFile/MasterFiles/Customer/Email/",
			"AuditFile/MasterFiles/Customer/Website/", "AuditFile/MasterFiles/Supplier/SupplierTaxID/",
			"AuditFile/MasterFiles/Supplier/CompanyName/", "AuditFile/MasterFiles/Supplier/Contact/",
			"AuditFile/MasterFiles/Supplier/BillingAddress/BuildingNumber/",
			"AuditFile/MasterFiles/Supplier/BillingAddress/StreetName/",
			"AuditFile/MasterFiles/Supplier/BillingAddress/AddressDetail/",
			"AuditFile/MasterFiles/Supplier/BillingAddress/City/",
			"AuditFile/MasterFiles/Supplier/BillingAddress/PostalCode/",
			"AuditFile/MasterFiles/Supplier/BillingAddress/Region/",
			"AuditFile/MasterFiles/Supplier/BillingAddress/Country/",
			"AuditFile/MasterFiles/Supplier/ShipFromAddress/BuildingNumber/",
			"AuditFile/MasterFiles/Supplier/ShipFromAddress/StreetName/",
			"AuditFile/MasterFiles/Supplier/ShipFromAddress/AddressDetail/",
			"AuditFile/MasterFiles/Supplier/ShipFromAddress/City/",
			"AuditFile/MasterFiles/Supplier/ShipFromAddress/PostalCode/",
			"AuditFile/MasterFiles/Supplier/ShipFromAddress/Region/",
			"AuditFile/MasterFiles/Supplier/ShipFromAddress/Country/", "AuditFile/MasterFiles/Supplier/Telephone/",
			"AuditFile/MasterFiles/Supplier/Fax/", "AuditFile/MasterFiles/Supplier/Email/",
			"AuditFile/MasterFiles/Supplier/Website/", "AuditFile/MasterFiles/TaxTable/TaxTableEntry/Description/",
			"AuditFile/GeneralLedgerEntries/Journal/Description/",
			"AuditFile/GeneralLedgerEntries/Journal/Transaction/SourceID/",
			"AuditFile/GeneralLedgerEntries/Journal/Transaction/Description/",
			"AuditFile/GeneralLedgerEntries/Journal/Transaction/Lines/DebitLine/Description/",
			"AuditFile/GeneralLedgerEntries/Journal/Transaction/Lines/CreditLine/Description/",
			"AuditFile/SourceDocuments/Payments/Payment/Description/",
			"AuditFile/SourceDocuments/Payments/Payment/DocumentStatus/SourceID/",
			"AuditFile/SourceDocuments/Payments/Payment/SourceID/",
			"AuditFile/SourceDocuments/Payments/Payment/Line/SourceDocumentID/Description/"));

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

		AESStreamCipher cipher = cipherInitialization();

		XMLInputFactory2 xmlif = staxFactoryInitialization(input);

		XMLStreamReader xmlr = null;

		try (InputStream targetStream = new FileInputStream(new File(input));
				Reader reader = readerInitialization(input, CHARSET);
				FileWriter writer = writerInitialization(output, CHARSET);) {

			xmlr = xmlif.createXMLStreamReader(targetStream, CHARSET.name());

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
			AESStreamCipher cipher, IterationParameters iParam) throws IOException, XMLStreamException {

		/*
		 * System.out.println("EVENT:[" + xmlr.getLocation().getLineNumber() + "][" +
		 * xmlr.getLocation().getColumnNumber() + "] " + xmlr.getEventType());
		 */
		try {
			switch (xmlr.getEventType()) {

				case XMLStreamConstants.START_ELEMENT:
					iParam.setNotCiphered(false);
					iParam.setHasText(false);
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

						if (elementsToCypher.contains(iParam.getCurrentBranch())) {
							iParam.setElementToCipher(elementsToCypher.contains(iParam.getCurrentBranch()));
							iParam.setElementToCipher(true);
						}
					}

					writeToOutput(xmlr, reader, writer, iParam);
					iParam.setStartElementOffset(xmlr.getLocation().getCharacterOffset());

					break;

				case XMLStreamConstants.CHARACTERS:
					if (xmlr.getText().length() > 0) {
						// System.out.println("CHARACTERS EVENT - Text Characters ->
						// "+xmlr.getTextCharacters().toString());
						iParam.setHasText(true);
						writeToOutput(xmlr, reader, writer, iParam);

						if (iParam.isElementToCipher()) {
							iParam.setValueStart(xmlr.getLocation().getCharacterOffset());
						}
					}
					break;

				case XMLStreamConstants.END_ELEMENT:
					if (iParam.isElementToCipher()) {

						/*
						 * System.out.println("END_ELEMENT=Line:" + xmlr.getLocation().getLineNumber() +
						 * ",Column:" + xmlr.getLocation().getColumnNumber() + ",Offset:" +
						 * xmlr.getLocation().getCharacterOffset()+ " LocalName -> "+
						 * xmlr.getLocalName() + " Start Element Offset " +
						 * iParam.getStartElementOffset() + " RealValue Length " +
						 * iParam.getValueLenght() );
						 * 
						 * System.out.println("branch: " + iParam.getCurrentBranch());
						 */

						iParam.setValueEnd(xmlr.getLocation().getCharacterOffset());

						if (iParam.getStartElementOffset() == xmlr.getLocation().getCharacterOffset()
								|| !iParam.isHasText()) {
							if (iParam.getPreviousElementEnd() > 0
									&& iParam.getPreviousElementEnd() >= iParam.getValueStart()) {
								iParam.setValueStart(iParam.getPreviousElementEnd());
							}
							iParam.setNotCiphered(true);
						}

						int realValueLenght = iParam.getValueLenght();
						if (realValueLenght > 0) {
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
							// System.out.println(" Value Real -> "+ valueReal+"\n\n");
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

		// xmlif.setProperty(XMLInputFactory2.P_PRESERVE_LOCATION, Boolean.TRUE);

		xmlif.configureForConvenience();

		xmlif.setProperty(XMLInputFactory2.P_REPORT_PROLOG_WHITESPACE, Boolean.FALSE);

		return xmlif;
	}

	private static AESStreamCipher cipherInitialization() throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());

		AESStreamCipher cipher = new AESStreamCipher(Cipher.getInstance("AES/ECB/NoPadding", "BC"));

		byte[] keyBytes = Base64.getDecoder().decode(keyB64);

		byte[] ivBytes = Base64.getDecoder().decode(ivB64);

		SecretKey secKey = new SecretKeySpec(keyBytes, "AES");
		cipher.init(!cipherOper, secKey, ivBytes);

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

	private static String cipher(AESStreamCipher cipher, String text)
			throws UnsupportedEncodingException, ShortBufferException {
		byte[] textBytes = text.getBytes(CHARSET);
		byte[] cipherTextBytes = new byte[textBytes.length];
		cipher.encrypt(textBytes, cipherTextBytes);
		String cipherTextString = Base64.getEncoder().encodeToString(cipherTextBytes);
		return cipherTextString;
	}

	private static String decipher(AESStreamCipher cipher, String text)
			throws UnsupportedEncodingException, ShortBufferException {
		byte[] cipherTextBytes = Base64.getDecoder().decode(text);
		byte[] decipheredBytes = new byte[cipherTextBytes.length];
		cipher.encrypt(cipherTextBytes, decipheredBytes);
		String decipherTextString = new String(decipheredBytes, CHARSET);
		return decipherTextString;

	}

}