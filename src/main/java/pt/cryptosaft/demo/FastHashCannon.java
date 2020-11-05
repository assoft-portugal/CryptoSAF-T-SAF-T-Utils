package pt.cryptosaft.demo;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.xml.XMLConstants;
import javax.xml.bind.DatatypeConverter;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLResolver;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer11_OmitCommentsTransformer;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.CanonicalizerBase;

public class FastHashCannon {

	private static String input = null;
	private static FileOutputStream fileOutputStream = null;
	private static String outputFile = null;
	private static CanonicalizerBase canonicalizerBase = null;
	private static XMLEventReader xmlSecEventReader = null;
	private static BufferedOutputStream bos = null;
	private static InputStream inputStream = null;

	public static void main(String[] args) throws Exception {

		long start = System.currentTimeMillis();
		System.out.println("Start ");

		try {
			input = args[0];
			outputFile = input + ".can.xml";
			System.out.println("Input File " + input);
			System.out.println("Output File " + outputFile);
		} catch (ArrayIndexOutOfBoundsException ex) {
			printUsage();
			System.exit(0);
		}

		// Initialize org.apache.xml.security.Init
		org.apache.xml.security.Init.init();

		// Prepare File to be read
		prepareToReadFile();

		// Prepare OutputFile
		getOutputFile();

		// Get CanonicalizerBase
		getCanonicalizer();

		// Get XMLEventReader prepare to Canonicalize File
		prepareToCanonicalizeFile();

		System.out.println("Start Canonicalization of " + input);

		canonicalizeFile();

		System.out.println("Canonicalization Done in: " + calculateDuration(start) + " seconds");

		// Calculate File Hash
		byte[] sha256Digest = calculateSh256Digest(outputFile);
		System.out.println("Cannonical File Hash -> " + new String(Base64.getEncoder().encode(sha256Digest)));
		System.out.println("Cannonical File Hash -> " + DatatypeConverter.printHexBinary(sha256Digest));
		System.out.println("Total time: " + calculateDuration(start) + " seconds");

	}

	private static long calculateDuration(long start) {
		return (System.currentTimeMillis() - start) / 1000;
	}

	private static void printUsage() {
		System.out.println("usage: java pt.cryptosaft.demo.FastHashCannon <input xml file>");
	}

	private static byte[] calculateSh256Digest(String inputFile) throws NoSuchAlgorithmException, IOException {
		int byteNumber = 4096;
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		sha256.reset();
		BufferedInputStream outStream = new BufferedInputStream(new FileInputStream(new File(inputFile)));
		int count;
		byte[] read = new byte[byteNumber];	
		try {
			while ((count = outStream.read(read)) > 0) {
				sha256.update(read, 0, count);
			}
		}
		finally {
			outStream.close();
		}
		return sha256.digest();

	}

	private static void prepareToReadFile() throws FileNotFoundException {
		File initialFile = new File(input);
		inputStream = new FileInputStream(initialFile);
	}

	private static void canonicalizeFile() throws XMLStreamException, IOException {
		while (xmlSecEventReader.hasNext()) {
			XMLSecEvent xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
			canonicalizerBase.transform(xmlSecEvent);
		}
		fileOutputStream.close();
	}

	private static void getCanonicalizer() throws XMLSecurityException {
		canonicalizerBase = new Canonicalizer11_OmitCommentsTransformer();
		canonicalizerBase.setOutputStream(bos);
	}

	private static void getOutputFile() throws FileNotFoundException {
		fileOutputStream = new FileOutputStream(new File(outputFile));
		bos = new BufferedOutputStream(fileOutputStream);
	}

	private static void prepareToCanonicalizeFile() throws Exception {

		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
		XMLResolver xmlResolver = new XMLResolver() {
			@Override
			public Object resolveEntity(String publicID, String systemID, String baseURI, String namespace)
					throws XMLStreamException {
				return this.getClass().getClassLoader()
						.getResourceAsStream("org/apache/xml/security/c14n/in/" + systemID);
			}
		};
		xmlInputFactory.setXMLResolver(xmlResolver);
		xmlSecEventReader = xmlInputFactory.createXMLEventReader(inputStream);
	}
}
