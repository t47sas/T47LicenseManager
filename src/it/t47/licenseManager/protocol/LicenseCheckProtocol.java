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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.t47.utils.MachineID;

public class LicenseCheckProtocol
{
	public static final String CLASS_DECRYPTION_KEY = "__class_decryption_key";
	
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

		LicenseParams licenseParams = checker.checkLicense (UUID, machineID, codeID, customData);
		if (licenseParams != null)
		{
			Map <String, Object> params = new HashMap <String, Object> ();
			params.putAll (licenseParams);
			params.put (CLASS_DECRYPTION_KEY, licenseParams.getClassDecryptionKey ());
			String paramsString = mapper.writeValueAsString (params);

			Cipher encryptCipher = Cipher.getInstance("RSA");
			encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
			return Base64.getEncoder ().encodeToString (encryptCipher.doFinal (paramsString.getBytes ()));
		}
		else
			return null;
	}
	
	public static LicenseParams checkLicense (String url, String UUID, String publicKeyBase64, Class <?> [] classes) throws ClassNotFoundException, NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
	{
		List <Class <?>> checkPool = new ArrayList <Class <?>> ();
		for (Class <?> c : classes)
			checkPool.add (c);
		checkPool.add (LicenseCheckProtocol.class);
		checkPool.add (MachineID.class);
		String [] ids = MachineID.getID (checkPool);
		String machineID = ids [0];
		String codeID = ids [1];

		try
		{
			byte [] pub = Base64.getDecoder ().decode (publicKeyBase64);
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec (pub);
			PublicKey publicKey = keyFactory.generatePublic (publicKeySpec);
			
			Map <String, String> requestMap = new HashMap <String, String> ();
			requestMap.put ("UUID", UUID);
			requestMap.put ("machineID", machineID);
			requestMap.put ("codeID", codeID);
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

				LicenseParams ret = new LicenseParams ();
				ret.putAll (params);
				ret.setClassDecryptionKey ((String) params.remove (CLASS_DECRYPTION_KEY));
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
