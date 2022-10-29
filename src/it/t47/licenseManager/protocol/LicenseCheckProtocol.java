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

package it.t47.licenseManager.protocol;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.core.DecoratingClassLoader;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.t47.utils.AES256Util;
import it.t47.utils.MachineID;

/**
 * Protocol Manager
 * Reference protocol implementation
 * designed to be used both by licensed software (client) and license server
 */

public class LicenseCheckProtocol
{
	private static final String CLASS_DECRYPTION_KEY = "__class_decryption_key";
	private static final String SERVER_COMMON_KEY = "__server_common_key";
	private static final String CLIENT_COMMON_KEY = "__client_common_key";
	
	private static ObjectMapper mapper = new ObjectMapper ();
	private static KeyFactory keyFactory;
	
	static
	{
		try
		{
			keyFactory = KeyFactory.getInstance ("RSA");
		}
		catch (Exception e)
		{
			e.printStackTrace ();
		}
	}

	/**
	 * License Server side method
	 *
	 * @param request			the value passed by licensed software (licensed software passes a JSON object as {'request': 'XXX' }, only XXX should be passed to the method)
	 * @param privateKeyBase64 	license server RSA private key, Base64 encoded
	 * @param checker			a LicenseChecker object, used to check license parameters
	 * @param customData		custom values (if any) to be passed to the LicenseChecker
	 * @return the value that should be transmitted back to the licensed software after inserting it in a JSON object as {data: <returned string, if valid>, error: <error string, if any>}: if no error has been thrown, null value should be passed as error
	 */
	public static String manageRequest (String request, String privateKeyBase64, LicenseChecker checker, Object... customData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, JsonMappingException, JsonProcessingException, InvalidKeySpecException
	{
		byte [] prv = Base64.getDecoder ().decode (privateKeyBase64);
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec (prv);
		PrivateKey privateKey = keyFactory.generatePrivate (privateKeySpec);
		
		Cipher decryptCipher = Cipher.getInstance ("RSA");
		decryptCipher.init (Cipher.DECRYPT_MODE, privateKey);
		String rq = new String (decryptCipher.doFinal (Base64.getDecoder ().decode (request)));
		
		@SuppressWarnings ("unchecked")
		Map <String, Object> requestData = mapper.readValue (rq, Map.class);
		String UUID = (String) requestData.get ("UUID");
		String machineID = (String) requestData.get ("machineID");
		String codeID = (String) requestData.get ("codeID");

		byte [] clientRandomKey = Base64.getDecoder ().decode ((String) requestData.get (CLIENT_COMMON_KEY));
		byte [] serverRandomKey = new byte [8];
		new SecureRandom ().nextBytes (serverRandomKey);
		
		byte [] fullKey = new byte [16];
		for (int a = 0; a < fullKey.length / 2; a ++)
		{
			fullKey [a] = clientRandomKey [a];
			fullKey [a + fullKey.length / 2] = serverRandomKey [a];
		}
		SecretKeySpec AESKey = AES256Util.createKey (fullKey);

		LicenseParams licenseParams = checker.checkLicense (UUID, machineID, codeID, customData);
		if (licenseParams != null)
		{
			byte [] cdc = AES256Util.encrypt (Base64.getDecoder ().decode (licenseParams.getClassDecryptionKey ()), AESKey);
			String classDecryptionKey = Base64.getEncoder ().encodeToString (cdc);

			Map <String, Object> params = new HashMap <String, Object> ();
			params.putAll (licenseParams);
			params.put (CLASS_DECRYPTION_KEY, classDecryptionKey);			
			params.put (SERVER_COMMON_KEY, Base64.getEncoder ().encodeToString (serverRandomKey));
			String paramsString = mapper.writeValueAsString (params);

			Cipher encryptCipher = Cipher.getInstance("RSA");
			encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
			return Base64.getEncoder ().encodeToString (encryptCipher.doFinal (paramsString.getBytes ()));
		}
		else
			return null;
	}

	/**
	 * Licensed software side method
	 * 
	 * @param url					URL of the license manager that with manage the license verification (a POST call will be performed)
	 * @param UUID					License UUID
	 * @param publicKeyBase64		License server public key, base64 encoded
	 * @param classes				classes to be checked for alteration
	 * @param encryptedClassNames	name of encrypted classes to be loaded
	 * @return a LicenseParams object containing custom license params (if any: i.e. expiration) and the encoded classes decryption key (to be used with provided EncryptedClassLoaders)
	 */	
	public static LicenseParams checkLicense (String url, String UUID, String publicKeyBase64, Class <?> [] classes, String [] encryptedClassNames) throws ClassNotFoundException, NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		List <Class <?>> checkPool = new ArrayList <Class <?>> ();
		for (Class <?> c : classes)
			checkPool.add (c);
		checkPool.add (LicenseCheckProtocol.class);
		checkPool.add (MachineID.class);
		checkPool.add (AES256Util.class);
		checkPool.add (LicenseCheckProtocol.class);
		checkPool.add (LicenseParams.class);
		checkPool.add (LicenseChecker.class);
		String [] ids = MachineID.getIDs (checkPool);
		String machineID = ids [0];
		String codeID = ids [1];

		boolean inSpring = LicenseParams.class.getClassLoader ().getClass ().getName ().startsWith ("org.springframework");		

		byte [] randomKey = new byte [8];
		new SecureRandom ().nextBytes (randomKey);

		try
		{
			byte [] pub = Base64.getDecoder ().decode (publicKeyBase64);
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec (pub);
			PublicKey publicKey = keyFactory.generatePublic (publicKeySpec);
			
			Map <String, String> requestMap = new HashMap <String, String> ();
			requestMap.put ("UUID", UUID);
			requestMap.put ("machineID", machineID);
			requestMap.put ("codeID", codeID);
			requestMap.put (CLIENT_COMMON_KEY, Base64.getEncoder ().encodeToString (randomKey));
			ObjectMapper om = new ObjectMapper ();
			String payload = om.writeValueAsString (requestMap);

			Cipher encryptCipher = Cipher.getInstance ("RSA");
			encryptCipher.init (Cipher.ENCRYPT_MODE, publicKey);
			payload = Base64.getEncoder ().encodeToString (encryptCipher.doFinal (payload.getBytes ()));

			Map <String, String> requestPayload = new HashMap <String, String> ();
			requestPayload.put ("request", payload);

			URL u = new URL (url);
			HttpURLConnection connection = (HttpURLConnection) u.openConnection ();

			connection.setRequestMethod ("POST");
			connection.setRequestProperty ("Content-Type", "application/json");

			connection.setDoOutput (true);
			PrintStream ps = new PrintStream (connection.getOutputStream ());
			ps.println (om.writeValueAsString (requestPayload));
			ps.close ();

			String response = "";
			BufferedReader br = new BufferedReader (new InputStreamReader (connection.getInputStream ()));
			for (String line = br.readLine (); line != null; line = br.readLine ())
				response += line;

			@SuppressWarnings ("unchecked")
			Map <String, String> responseMap = om.readValue (response, Map.class);
			String error = (String) responseMap.get ("error");
			if (error == null)
			{
				response = responseMap.get ("data").toString ();
				Cipher decryptCipher = Cipher.getInstance ("RSA");
				decryptCipher.init (Cipher.DECRYPT_MODE, publicKey);

				@SuppressWarnings ("unchecked")
				Map <String, Object> params = om.readValue (new String (decryptCipher.doFinal (Base64.getDecoder ().decode (response))), Map.class);
				
				byte [] serverRandomKey = Base64.getDecoder ().decode (params.remove (SERVER_COMMON_KEY).toString ());
				byte [] fullKey = new byte [16];
				for (int a = 0; a < fullKey.length / 2; a ++)
				{
					fullKey [a] = randomKey [a];
					fullKey [a + fullKey.length / 2] = serverRandomKey [a];
				}
				SecretKeySpec AESKey = AES256Util.createKey (fullKey);				
		
				byte [] cdc = Base64.getDecoder ().decode (params.remove (CLASS_DECRYPTION_KEY).toString ());
				String classDecryptionKey = Base64.getEncoder ().encodeToString (AES256Util.decrypt (cdc, AESKey));

				LicenseParams ret = new LicenseParams ();
				ret.putAll (params);
				
				ClassLoader cl = new ClassLoader ()
				{
					@Override
					public Class <?> findClass (String name) throws ClassNotFoundException
					{
						try
						{
							return Class.forName (name);
						}
						catch (ClassNotFoundException e)
						{
						}

						String path = name.replaceAll ("\\.", "/") + ".encrypted";
						try
						{
							byte [] data = LicenseParams.class.getClassLoader ().getResourceAsStream (path).readAllBytes ();
							data = AES256Util.decrypt (data, classDecryptionKey);
							return defineClass (name, data, 0, data.length);
						}
						catch (Exception e)
						{
							throw new ClassNotFoundException (name);
						}
					}
				};
				if (inSpring)
					cl = new DecoratingClassLoader ()
					{
						@Override
						public Class <?> findClass (String name) throws ClassNotFoundException
						{
							try
							{
								return Class.forName (name);
							}
							catch (ClassNotFoundException e)
							{
							}
							
							String path = name.replaceAll ("\\.", "/") + ".encrypted";
							try
							{
								byte [] data = LicenseParams.class.getClassLoader ().getResourceAsStream (path).readAllBytes ();
								data = AES256Util.decrypt (data, classDecryptionKey);
								return defineClass (name, data, 0, data.length);
							}
							catch (Exception e)
							{
								e.printStackTrace ();
								throw new ClassNotFoundException (name);
							}
						}
					};

				for (String className : encryptedClassNames) try
				{
					ret.getClassMap ().put (className, cl.loadClass (className));
				}
				catch (Exception e)
				{
					e.printStackTrace ();
				}
				
				return ret;
			}
			else
				System.err.println (error);
		}
		catch (Exception e)
		{
			e.printStackTrace ();
		}

		System.err.println ("cannot retrieve license details from " + url);
		return null;
	}
}
