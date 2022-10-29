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






T47LicenseManager is a license manager service for Java (and expecially Java over Spring Boot) projects.

T47LicenseManager is designed to manage

- per license UUID
- machine ID, computed over MAC addresses, to avoid unauthorized systems replication
- (selected) classes bytecode MD5 Hash, to avoid class decompiling and hacking
- encrypted class file support

T47LicenseManager is server-based: a T47LicenseManager protocol compatible server should be set up somewhere on the internet.

Basically, protocol phases are

1) the licensed server computes machine ID and bytecode ID and the first half of the decryption key of the encrypted classes decryption key (ECDK), and send them to the licensing server along with its UUID
2) these data are sent to the licensing server after encrypting it with the licensing serever's public key
3) the licensing server evaluates UUID, machine ID and bytecode ID and (eventually) sends back license properties (expiration...), the second half of the decryption key of the ECDK and the so encrypted ECDK itself. Server response is encrypted via its private key
4) the licensed server decrypts ECDK and uses it to decript the encrypted classes and finally can use them: if the license parameteres are not verified, no decryption key is provided and encrypted classes cannot be used.

The project is based mainly on it.t47.licenseManager.protocol.LicenseCheckProtocol that implement the base protocol for both licensed software & licensing server.

Basic usage:
Project classes provide services for both licensed server (the one whom license should be verified) and licensing server (the one that should verify the provided license params and decide if a license is valid or not).

- Licensed software:

call it.t47.licenseManager.protocol.LicenseCheckProtocol.checkLicense static method passing
- license server service URL (a POST request will be made)
- license UUID
- license server public key (RSA algorithm is used), Base64 encoded
- array of classes to check for bytecode integrity (will be hashed in MD5, after including LicenseManager main classes also)
- array of encrypted classes names the user wants to decypt

the method returns a LicenseParams object containig
- custom license parameters (if any, for example expiration...)
- a map containing the requestet classes read once decrypted


- License manager sever:

call it.t47.licenseManager.protocol.LicenseCheckProtocol.manageRequest static method passing
- the "request" param passed with POST method (json encoded) by checkLicense method
- license server private key (RSA algorithm is used), Base64 encoded
- a LicenseChecker object (see it.t47.licenseManager.protocol.LicenseChecker interface): this object will receive UUID, machineID and classes bytecode ID  other than some custom other params) and will retunr a LicenseParam object with custom license parameters (if any, for example expiration date) or null if the license cannot be verified
- custom params to be passed to the LicenseChecker object
the method returns an encoded string to be passed to the calling server in an json object built as { data: <encoded string>, error: <error - if any - or null otherwise> }
	
- Class files encryption:

Create an AES256 key and encode it in Base64 format.

Use it.t47.utils.AES256Util class to ancrypt/decrypt classes.

Call the class from command line with the following command line parameters
- command ('e' to encrypt, 'd' to decrypt)
- AES254 key in base64 encoding
- file to encrypt / decrypt (according with 'command' parameter)
- destination file

In order to be recognized by the Encrypted Class loaders provided, encrypted classes should have ".encrypt" extension instead of ".class" one and be located in the same position of plain ".class" file.
Of course original plain class files should be removed from the distribution.
