package it.t47.licenseManager.protocol;

import java.util.HashMap;

public class LicenseParams extends HashMap <String, Object>
{
	private static final long serialVersionUID = 1L;

	private String classDecryptionKey;

	public String getClassDecryptionKey ()
	{
		return classDecryptionKey;
	}

	public void setClassDecryptionKey (String classDecryptionKey)
	{
		this.classDecryptionKey = classDecryptionKey;
	}
}
