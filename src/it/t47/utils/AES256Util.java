package it.t47.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Base64;

public class AES256Util
{
	private static Cipher encrypter, decrypter;
	
	public static void reset ()
	{
		encrypter = null;
		decrypter = null;
	}
	
	public static byte [] decrypt (byte [] data, String base64Key)
	{
		if (data == null || data.length == 0)
			return data;
		try
		{
			if (decrypter == null)
			{
			    SecretKeySpec secretKey = new SecretKeySpec (Base64.getDecoder ().decode (base64Key), "AES");
				byte [] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
				IvParameterSpec ivspec = new IvParameterSpec (iv);

				decrypter = Cipher.getInstance ("AES/CBC/PKCS5PADDING");
				decrypter.init (Cipher.DECRYPT_MODE, secretKey, ivspec);
			}
			return decrypter.doFinal (data);
		}
		catch (Exception e)
		{
			System.out.println ("Error while decrypting: " + e.toString ());
		}
		return null;
	}

	public static byte [] encrypt (byte [] data, String base64Key)
	{
		try
		{
			if (encrypter == null)
			{
			    SecretKeySpec secretKey = new SecretKeySpec (Base64.getDecoder ().decode (base64Key), "AES");
				byte [] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
				IvParameterSpec ivspec = new IvParameterSpec (iv);

				encrypter = Cipher.getInstance ("AES/CBC/PKCS5Padding");
				encrypter.init (Cipher.ENCRYPT_MODE, secretKey, ivspec);
			}
			return encrypter.doFinal (data);
		}
		catch (Exception e)
		{
			System.out.println ("Error while encrypting: " + e.toString ());
		}
		return null;
	}
	
	public static void main (String [] args)
	{
		String command = args [0];
		String key = args [1];
		String fileIn = args [2];
		String fileOut = args [3];
		
		try (FileInputStream fis = new FileInputStream (fileIn); FileOutputStream out = new FileOutputStream (fileOut))
		{
			byte [] data = fis.readAllBytes ();
		
			if (command.equals ("e"))
				out.write (encrypt (data, key));
			else if (command.equals ("d"))
				out.write (decrypt (data, key));
		}
		catch (Exception e)
		{
			e.printStackTrace ();
		}
	}
}
