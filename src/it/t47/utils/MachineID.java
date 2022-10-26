package it.t47.utils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.NetworkInterface;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javassist.ClassPool;

public class MachineID
{
	public static String [] getID (List <Class <?>> pool)
	{
		try
		{
			MessageDigest md5 = MessageDigest.getInstance ("MD5");

			String [] ret = new String [] {"", ""};
			ByteArrayOutputStream main = new ByteArrayOutputStream ();
			
			List <String> addresses = new ArrayList <String> ();
			for (Enumeration <NetworkInterface> en = NetworkInterface.getNetworkInterfaces (); en.hasMoreElements ();)
			{
				byte [] mac = en.nextElement ().getHardwareAddress ();
				if (mac != null)
					addresses.add (Base64.getEncoder ().encodeToString (mac));
			}
			Collections.sort (addresses);
			for (String address: addresses)
				main.write (address.getBytes ());
			ret [0] = Base64.getEncoder ().encodeToString (md5.digest (main.toByteArray ()));
			main.close ();

			if (pool.size () > 0)
			{
				main = new ByteArrayOutputStream ();
				ClassPool cp = ClassPool.getDefault ();
				for (Class <?> c : pool)
				{
					ByteArrayOutputStream out = new ByteArrayOutputStream ();
					cp.get (c.getName ()).getClassFile ().write (new DataOutputStream (out));
					out.close ();
					main.write (out.toByteArray ());
				}
				ret [1] = Base64.getEncoder ().encodeToString (md5.digest (main.toByteArray ()));
				main.close ();
			}

			return ret;
		}
		catch (Exception e)
		{
			e.printStackTrace ();
			return null;
		}
	}
}
