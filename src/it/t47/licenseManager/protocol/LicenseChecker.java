package it.t47.licenseManager.protocol;

public interface LicenseChecker
{
	public LicenseParams checkLicense (String UUID, String machineID, String codeID, Object... customData);
}
