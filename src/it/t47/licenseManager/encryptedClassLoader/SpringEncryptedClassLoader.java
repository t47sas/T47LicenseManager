package it.t47.licenseManager.encryptedClassLoader;

import org.springframework.core.DecoratingClassLoader;

import it.t47.utils.AES256Util;

public class SpringEncryptedClassLoader extends DecoratingClassLoader
{
	private String key;

	public SpringEncryptedClassLoader (String key, ClassLoader parent)
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
