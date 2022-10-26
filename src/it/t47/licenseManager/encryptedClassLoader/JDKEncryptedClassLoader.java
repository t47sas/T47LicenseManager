package it.t47.licenseManager.encryptedClassLoader;

import it.t47.utils.AES256Util;

public class JDKEncryptedClassLoader extends ClassLoader
{
	String key;

	public JDKEncryptedClassLoader (String key, ClassLoader parent)
	{
		super (parent);
		this.key = key;
	}

	@Override
	public Class <?> findClass (String name) throws ClassNotFoundException
	{
		String path = name.replaceAll ("\\.", "/") + ".encrypted";
		try
		{
			byte [] data = getParent ().getResourceAsStream (path).readAllBytes ();
			data = AES256Util.decrypt (data, key);
			return defineClass (name, data, 0, data.length);
		}
		catch (Exception e)
		{
			throw new ClassNotFoundException (name);
		}
	}

}
