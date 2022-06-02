package ui;

import java.io.FileOutputStream;  
import java.io.ObjectOutputStream;  
import java.security.Key;  
import java.security.KeyPair;  
import java.security.KeyPairGenerator;  
import java.security.NoSuchAlgorithmException;  
import java.security.SecureRandom;  

import sun.misc.BASE64Encoder; 

public class Main {
	
	// El algoritmo de cifrado designado es RSA 
    private static final String ALGORITHM = "RSA";  
    // Longitud de la clave, utilizada para inicializar 
    private static final int KEYSIZE = 1024;  
    // Designar archivos de almacenamiento de claves públicas 
    private static String PUBLIC_KEY_FILE = "PublicKey";  
    // Designar archivo de almacenamiento de clave privada 
    private static String PRIVATE_KEY_FILE = "PrivateKey";  

	public static void main(String[] args) throws Exception {
		generateKeyPair();  
        genKeyPair();  

	}
	
	public static void generateKeyPair() throws Exception { 
		//SecureRandom secureRandom = new SecureRandom();  
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);  
		
		 //keyPairGenerator.initialize(KEYSIZE, secureRandom);
		 keyPairGenerator.initialize(KEYSIZE); 
		 KeyPair keyPair = keyPairGenerator.generateKeyPair();  
		 Key publicKey = keyPair.getPublic();  
		 Key privateKey = keyPair.getPrivate();  
		 ObjectOutputStream oos1 = null;  
	        ObjectOutputStream oos2 = null;  
	        try {  
	        	 oos1 = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));  
	             oos2 = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE));  
	             oos1.writeObject(publicKey);  
	             oos2.writeObject(privateKey);  
	         } catch (Exception e) {  
	             throw e;  
	         } finally {   oos1.close();  
	            oos2.close();  
	         }  
	     } 
	
	 public static void genKeyPair() throws NoSuchAlgorithmException {  
		 SecureRandom secureRandom = new SecureRandom();  
		 KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);  
		 keyPairGenerator.initialize(KEYSIZE, secureRandom);  
	     //keyPairGenerator.initialize(KEYSIZE);  
		 KeyPair keyPair = keyPairGenerator.generateKeyPair();  
		 Key publicKey = keyPair.getPublic(); 
		 Key privateKey = keyPair.getPrivate();  
	     byte[] publicKeyBytes = publicKey.getEncoded();  
	     byte[] privateKeyBytes = privateKey.getEncoded();  
	  
	     String publicKeyBase64 = new BASE64Encoder().encode(publicKeyBytes);  
	     String privateKeyBase64 = new BASE64Encoder().encode(privateKeyBytes);  
	  
	     System.out.println("publicKeyBase64.length():" + publicKeyBase64.length());  
	     System.out.println("publicKeyBase64:" + publicKeyBase64);  
	  
	     System.out.println("privateKeyBase64.length():" + privateKeyBase64.length());  
	     System.out.println("privateKeyBase64:" + privateKeyBase64);  
	 }
	     
}
