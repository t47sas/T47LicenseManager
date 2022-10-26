Copyright 2022, Tancredi Canonico

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.






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

use the proper encrypted ClassLoader (SpringEncryptedClassLoader or JDKEncryptedClassLoader) to decrypt and load encrypted class files (see below for encryption utility class).

- License manager:
call it.t47.licenseManager.protocol.LicenseCheckProtocol.manageRequest static method passing
	- the "request" param passed with POST method (json encoded) by checkLicense method
	- license server private key (RSA algorithm is used), Base64 encoded
	- a LicenseChecker object (see it.t47.licenseManager.protocol.LicenseChecker interface): this object will receive UUID, machineID and classes bytecode ID - other than some custom other params) and will retunr a LicenseParam object with custom license parameters (if any, for example expiration date) or null if the license cannot be verified
	- custom params to be passed to the LicenseChecker object
	
	returns an encoded string to be passed to the calling server in an json object built as 
	{ data: <encoded string>, error: <error - if any - or null otherwise> }
	
- Class files encryption:

Create an AES256 key and encode it in Base64 format.

Use it.t47.utils.AES256Util class to ancrypt/decrypt classes.

Call the class from command line with the following command line parameters
	command ('e' to encrypt, 'd' to decrypt)
	AES254 key in base64 encoding
	file to encrypt / decrypt (according with 'command' parameter)
	destination file

In order to be recognized by the Encrypted Class loaders provided, encrypted classes should have ".encrypt" extension instead of ".class" one and be located in the same position of plain ".class" file.
Of course original plain class files should be removed from the distribution.
