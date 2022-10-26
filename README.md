T47LicenseManager is a license manager service for Java (and expecially JAva over Spring Boot) projects.

T47LicenseManager is designed to manage

- per license UUID
- machine ID, computed over MAC addresses, to avoid unauthorized systems replication
- (selected) classes bytecode MD5 Hash, to avoid class decompiling and hacking
- encrypted class file support

T47LicenseManager is server-based: a T47LicenseManager protocol compatible server should be set up somewhere on the internet.

Basically, protocol phases are

1) the licensed server conputes machine ID and bytecode ID, and send them to the licensing server along with its UUID
2) these data are sent to the licensing server after encrypting it with the licensing serever's public key
3) the licensing server evaluates UUID, machine ID and bytecode ID and (eventually) sends back license properties (expiration...) and the encrypted classes decryption key. Server response is encrypted via its private key
4) the licensed server uses the classes decryption key to decript the encrypted classes and finally can use them

The project is based mainly on three classes:

- it.t47.licenseManager.protocol.LicenseCheckProtocol: implement the base protocol for both licensed software & licensing server.
- it.t47.licenseManager.encryptedClassLoader.SpringEncryptedClassLoader: ClassLoader for encrypted .class files, to be used in SpringBoot environment.
- it.t47.licenseManager.encryptedClassLoader.JDKEncryptedClassLoader: ClassLoader for encrypted .class files, to be used in all other cases.

Basic usage:

- Licensed software:
call it.t47.licenseManager.protocol.LicenseCheckProtocol.checkLicense static method passing
	- license server service URL (a POST request will be made)
	- license UUID
	- license server public key (RSA algorithm is used), Base64 encoded
	- array of classes to check for bytecode integrity (will be hashed in MD5, after including LicenseManager main classes also)

	returns a LicenseParams object containig
	- custom license parameters (if any, for example expiration...)
	- decryption key for encrypted class files
	or null if the license verification fails

use the proper encrypted ClassLoader (SpringEncryptedClassLoader or JDKEncryptedClassLoader) to decrypt and load encrypted class files (see below for encryption utility class)

- License manager:
call it.t47.licenseManager.protocol.LicenseCheckProtocol.manageRequest static method passing
	- the "request" param passed with POST method (json encoded) by checkLicense method
	- license server private key (RSA algorithm is used), Base64 encoded
	- a LicenseChecker object (see it.t47.licenseManager.protocol.LicenseChecker interface): this object will receive UUID, machineID and classes bytecode ID - other than some custom other params) and will retunr a LicenseParam object with custom license parameters (if any, for example expiration date) or null if the license cannot be verified
	- custom params to be passed to the LicenseChecker object
	
	returns an encoded string to be passed to the 
