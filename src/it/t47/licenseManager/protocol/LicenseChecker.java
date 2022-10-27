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

/**
 * LicenseChecker interface
 * a LicenseChecker is an object that can make license params validations
 * LicenseChecker can take decisions about the license validity basing on license unique identifier,
 * machineID and codeID
 * Moreover some other custom params can be passed to the LicenseChecker (for licensing purposes, for example)
 */

public interface LicenseChecker
{
	/**
	 * checks the license params
	 * 
	 * @param		UUID		license UUID
	 * @param		machineID	identifier of the system the software is running on (i.e. the one returned by MachineID utility class)
	 * @param		codeID	identifier of the mail classes used (i.e. the one returned by MachineID utility class)
	 * @return		LicenseParams object (extends Map <String, Object>) that can be used to return custom parameters (if any) related to the license (i.e. expiration). Should return null if the given parameters do not correspond to a valide license
	 */
	public LicenseParams checkLicense (String UUID, String machineID, String codeID, Object... customData);
}
