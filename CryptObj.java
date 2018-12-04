package crypt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Formatter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CryptObj {
	
    public static String encrypt(String key, String value) {
        try {
	        	byte[] b = new byte[16];
	        	b = Arrays.copyOf(key.getBytes(), 16);
	        	Cipher cipher = Cipher.getInstance("Blowfish");
	            SecretKeySpec skeySpec = new SecretKeySpec(b, "Blowfish");
	            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
	            byte[] encrypted = cipher.doFinal(value.getBytes());
	            String s = new String(Base64.getEncoder().encode(encrypted));
	            return s;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    public static String decrypt(String key, String encrypted) {
    	
        try {
        	
        	byte[] b = new byte[16];
        	b = Arrays.copyOf(key.getBytes(), 16);            

            Cipher cipher = Cipher.getInstance("Blowfish");
            SecretKeySpec skeySpec = new SecretKeySpec(b, "Blowfish");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);

            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    
    	
    }
    
    public static String sha1(String value) {
    	
    	try {
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			sha.reset();
			sha.update(value.getBytes());
			return byteToHex(sha.digest());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	return null;
    }
    
    public static String byteToHex(final byte[] hash)
    {
        Formatter formatter = new Formatter();
        for (byte b : hash)
        {
            formatter.format("%02x", b);
        }
        String result = formatter.toString();
        formatter.close();
        return result;
    }
    
	
}
