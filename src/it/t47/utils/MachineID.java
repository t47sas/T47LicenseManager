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

/*
 * MachineID utils
 * used to calculate the Machine ID and MD5 hash of a given list of classes (code ID).
 * the Machine ID is calculated as the MD5 hash of the concatenation of every MAC address, sorted alphabetically
 * the code ID is calculated as the MD5 has of the concatenation of every passed class file
 * uses javassist library to extract the .class file content from loaded class
 */

public class MachineID
{
	/*
	 * this method returns an array of two string: the first is the machine ID, the second is the code ID
	 * (refer to the prefious comment for further details)
	 */
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
