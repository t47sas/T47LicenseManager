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

import java.util.HashMap;
import java.util.Map;

/**
 * Object returned by the LicenseChecker object
 * it extends Map <String, Object> and can store custom parameters to send to the licensed system, for example expiration.
 * classDecryptionKey member is managed by the protocol manager and should not be compiled by users
 */
public class LicenseParams extends HashMap <String, Object>
{
	private static final long serialVersionUID = 1L;

	private String classDecryptionKey;
	private Map <String, Class <?>> classMap = new HashMap <String, Class <?>> ();

	public String getClassDecryptionKey ()
	{
		return classDecryptionKey;
	}

	public void setClassDecryptionKey (String classDecryptionKey)
	{
		this.classDecryptionKey = classDecryptionKey;
	}

	public Map <String, Class <?>> getClassMap ()
	{
		return classMap;
	}
}
