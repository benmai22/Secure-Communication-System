package sample;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Base64;
import java.util.Arrays;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
 
import javax.crypto.Mac;
import javax.xml.bind.DatatypeConverter;


public class Encryption
{
	private static final SecureRandom secureRandom = new SecureRandom();
	private static final String MAC_ALGORITHM = "HMACSHA256";
	private static final String HEX_MAC_KEY = "AEB908AA1CEDFFDEA1F255640A05EEF6";
	private static final int RANDOM_BYTES_LENGTH = 16;
	private static final String PROJECT_BASE_DIR = "/Users/benmai/Downloads/rsa-encryption/src/main/java/sample/";
	private static final String STRING_ENCODING = "ISO_8859_1";
	static private Base64.Encoder encoder = Base64.getEncoder();
    static SecureRandom srandom = new SecureRandom();

    static private void processFile(Cipher ci,InputStream in,OutputStream out)
	throws javax.crypto.IllegalBlockSizeException,
	       javax.crypto.BadPaddingException,
	       java.io.IOException
    {
	byte[] ibuf = new byte[1024];
	int len;
	while ((len = in.read(ibuf)) != -1) {
	    byte[] obuf = ci.update(ibuf, 0, len);
	    if ( obuf != null ) out.write(obuf);
	}
	byte[] obuf = ci.doFinal();
	if ( obuf != null ) out.write(obuf);
    }

    static private void processFile(Cipher ci,String inFile,String outFile)
	throws javax.crypto.IllegalBlockSizeException,
	       javax.crypto.BadPaddingException,
	       java.io.IOException
    {
	try (FileInputStream in = new FileInputStream(inFile);
	     FileOutputStream out = new FileOutputStream(outFile)) {
		processFile(ci, in, out);
	    }
    }
    
    // MAC Implementation
    
	  public byte[] encrypt(Key hexMacKey, String macAlgorithm)
		      throws Exception {		
	

			String inputFile = PROJECT_BASE_DIR+"input.txt.enc";
			byte[] encryptedText = Files.readAllBytes(Paths.get(inputFile));

			Mac mac = Mac.getInstance(macAlgorithm);
			mac.init(hexMacKey);

			byte[] macResult = mac.doFinal(encryptedText);

           System.out.println("Mac result:");
           System.out.println(new String(macResult));   		 
		    
			try (FileOutputStream out = new FileOutputStream(PROJECT_BASE_DIR+"mac.enc")) {
				out.write(macResult);
			    }		
			return macResult;
		  }

		  public String decrypt(Key hexMacKey,byte[] checkdata, String macAlgorithm)
		  throws Exception {		


		String inputFile = PROJECT_BASE_DIR+"input.txt.enc";
		byte[] encryptedText = Files.readAllBytes(Paths.get(inputFile));

		Mac mac = Mac.getInstance(macAlgorithm);
		mac.init(hexMacKey);

		byte[] macResult = mac.doFinal(encryptedText);

   		 
		
	   if (!MessageDigest.isEqual(macResult, checkdata)) {
		throw new RuntimeException("Message corrupted");
	  }else{
		System.out.println("Mac Verified result");
		System.out.println(new String(macResult));
	  }
		return "";
	  }	  
	  


    static private void doGenkey()
	throws java.security.NoSuchAlgorithmException,
	       java.io.IOException
    {
    System.out.println(PROJECT_BASE_DIR);
	int index = 0;
	KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	kpg.initialize(2048);
	KeyPair kp = kpg.generateKeyPair();
	try (FileOutputStream out = new FileOutputStream(PROJECT_BASE_DIR+"new.key")) {
		out.write(kp.getPrivate().getEncoded());
	    }

	try (FileOutputStream out = new FileOutputStream(PROJECT_BASE_DIR+"new.pub")) {
		out.write(kp.getPublic().getEncoded());
	    }
    }

    /* Larger data gives:
     *
     * javax.crypto.IllegalBlockSizeException: Data must not be longer
     * than 245 bytes
     */
    static private void doEncrypt()
	throws java.security.NoSuchAlgorithmException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       java.security.InvalidKeyException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {
	String pvtKeyFile = PROJECT_BASE_DIR+"new.key";
	String inputFile = PROJECT_BASE_DIR+"input.txt";
	byte[] bytes = Files.readAllBytes(Paths.get(pvtKeyFile));
	PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
	KeyFactory kf = KeyFactory.getInstance("RSA");
	PrivateKey pvt = kf.generatePrivate(ks);

	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.ENCRYPT_MODE, pvt);
	processFile(cipher, inputFile, inputFile + ".enc");
    }

    static private void doDecrypt()
	throws java.security.NoSuchAlgorithmException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       java.security.InvalidKeyException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {
	String pubKeyFile = PROJECT_BASE_DIR+"new.pub";
	String inputFile = PROJECT_BASE_DIR+"input.txt.enc";
	byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));
	X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
	KeyFactory kf = KeyFactory.getInstance("RSA");
	PublicKey pub = kf.generatePublic(ks);

	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.DECRYPT_MODE, pub);
	processFile(cipher, inputFile, inputFile + ".ver");
    }

    static private void doEncryptRSAWithAES()
	throws java.security.NoSuchAlgorithmException,
	       java.security.InvalidAlgorithmParameterException,
	       java.security.InvalidKeyException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {
	String pvtKeyFile = PROJECT_BASE_DIR+"new.key";
	String inputFile = PROJECT_BASE_DIR+"input.txt";	
	byte[] bytes = Files.readAllBytes(Paths.get(pvtKeyFile));
	PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
	KeyFactory kf = KeyFactory.getInstance("RSA");
	PrivateKey pvt = kf.generatePrivate(ks);

	KeyGenerator kgen = KeyGenerator.getInstance("AES");
	kgen.init(128);
	SecretKey skey = kgen.generateKey();

	byte[] iv = new byte[128/8];
	srandom.nextBytes(iv);
	IvParameterSpec ivspec = new IvParameterSpec(iv);

	try (FileOutputStream out = new FileOutputStream(inputFile + ".encrsa")) {
		{
		    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		    cipher.init(Cipher.ENCRYPT_MODE, pvt);
		    byte[] b = cipher.doFinal(skey.getEncoded());
		    out.write(b);
		    System.err.println("AES Key Length: " + b.length);
		}

		out.write(iv);
		System.err.println("IV Length: " + iv.length);

		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
		try (FileInputStream in = new FileInputStream(inputFile)) {
			processFile(ci, in, out);
		    }
	    }
    }

    static private void doDecryptRSAWithAES()
	throws java.security.NoSuchAlgorithmException,
	       java.security.InvalidAlgorithmParameterException,
	       java.security.InvalidKeyException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {

	String pubKeyFile = PROJECT_BASE_DIR+"new.pub";
	String inputFile = PROJECT_BASE_DIR+"input.txt.encrsa";
	byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));
	X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
	KeyFactory kf = KeyFactory.getInstance("RSA");
	PublicKey pub = kf.generatePublic(ks);

	try (FileInputStream in = new FileInputStream(inputFile)) {
		SecretKeySpec skey = null;
		{
		    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		    cipher.init(Cipher.DECRYPT_MODE, pub);
		    byte[] b = new byte[256];
		    in.read(b);
		    byte[] keyb = cipher.doFinal(b);
		    skey = new SecretKeySpec(keyb, "AES");
		}

		byte[] iv = new byte[128/8];
		in.read(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ci.init(Cipher.DECRYPT_MODE, skey, ivspec);

		try (FileOutputStream out = new FileOutputStream(inputFile+".verrsa")){
			processFile(ci, in, out);
		    }
	    }
    }

    static public void main(String[] args) throws Exception
    {
	doGenkey();
	//doEncrypt();
	//doDecrypt();
	//	doEncryptRSAWithAES();
	//	doDecryptRSAWithAES();
	
	//Encryption tester = new Encryption();
   // try {
	//KeyGenerator keyGen = KeyGenerator.getInstance("DES");
	//	SecureRandom secRandom = new SecureRandom();
	//	keyGen.init(secRandom);
	//	Key key = keyGen.generateKey();	
   //   tester.decrypt(key,data, MAC_ALGORITHM);
   
    //} catch (Exception e) {
      //e.printStackTrace();
    //}
	
    }
}
