/*
 * Copyright (c) 2022 Tancredi Canonico
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

package it.t47.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Base64;

/**
 * AES256 utils
 * used to encrypt/decrypt classes files
 * 
 * AES256 keys should be generate externally and passed encoded in base64 format
 */

public class AES256Util
{
	private static Cipher encrypter, decrypter;
	
	public static void reset ()
	{
		encrypter = null;
		decrypter = null;
	}

	/**
	 * performs AES256 decryption
	 * @param data			data to be decrpted
	 * @param base64Key		AES256 decription key, base64 encoded 
	 * @return decrypted data
	 */
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

	/**
	 * performs AES256 encryption
	 * @param data			data to be encrypted
	 * @param base64Key		AES256 encryption key, base64 encoded 
	 * @return encrypted data
	 */
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
	
	/**
	 * utility main method: performs encription or decription of the given file using the given class
	 * the first parameter (e/d) defines the operation to be performed
	 * output file name must be provided as last parameter
	 * 
	 * command line arguments summary:
	 * 		- operation ('e'/'d' for encrypting/decrypting))
	 * 		- AES256 key in base64 encoded format
	 * 		- input file name (to be encrypted / decrypted according with 1st param)
	 * 		- output file name
	 * 
	 * in order to be recognized by the EncryptedClassLoader classes, encrypted class files should
	 * have ".encrypt" extension instead of ".class" one
	 * and be located in the same location of the plain ".class" file
	 * Of course the ".class" file should be removed from the distribution
	 */
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
