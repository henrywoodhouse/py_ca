# Python private certificate authority
This module provides a private certificate authority which can generate it's own credentials and then create and sign CSR's for use elsewhere.

Python 3.6 or newer is required.

**Example usage:**
```python
from pyca import pyca

priv_ca = pyca()
priv_ca.generate() # Generates the root keys
priv_ca.save() # Saves root key and certificate
priv_ca.generate_csr() # Creates a CSR
priv_ca.sign_csr() # Signs the CSR using the root keys generated earlier
```
## Module Methods
### load(key_path, cert_path, password)
Loads a root certificate and key from the specified path  
**Parameters:**
* **key_path** - The path to the private key, defaults to './'
* **cert_path** - The path to the certificate, defaults to './'
* **password** - The password for the private key, if none is provided it will be prompted for

**Returns:**
	
### save(path, password_length, password)
Saves the root certificate and key in memory to the specified path  
**Parameters:**
* **path** - The folder to which the private key/certificate should be saved to, defaults to './'
* **password_length** - The length of the encryption password, defaults to 32 characters
* **password** - The password to be used to encrypt the private key, if none is provided it is prompted for

**Returns:**
* **password** - The password used to encrypt the private key
	

### generate(country_name, state, locality, organization, common_name, dns_name, validity)
Generates a private key and certificate for the root authority  
**Parameters:**
* **counrty_name** - The country name for the SSL certificate, defaults to 'XX'
* **state** - The state for the SSL certificate, defaults to 'Undefined'
* **locality** - The locality for the SSL certificate, defaults to 'Undefined'
* **organization** - The organization for the SSL certificate, defaults to 'Undefined'
* **common_name** - The common name for the SSL certificate, defaults to 'Undefined'
* **dns_name** - An additional DNS name for the SSL certificate, defaults to 'localhost'
* **validity** - The validity length for the SSL certificate, defaults to 365 days

**Returns:**

	
### reset()
Overwrites the private key and certificate stored in the object  
**Parameters:**

**Returns:**
	
### sign_csr(csr_path, cert_path, server)
Signs the supplied CSR using the root authorities private key  
**Parameters:**
* **csr_path** - The path to the CSR file, defaults to './csr.pem'
* **cert_path** - The path to the folder where the certificate is placed, defaults to './'
* **server** - A boolean value stating whether the certificate will be used on a server, defaults to False

**Returns:**
* **serial_id** - A unique key to identify the generated certificate with

### generate_csr(path, country_name, state, locality, organization, common_name, validity, password)
Generates a CSR  
**Parameters:**
* **counrty_name** - The country name for the SSL certificate, defaults to 'XX'
* **state** - The state for the SSL certificate, defaults to 'Undefined'
* **locality** - The locality for the SSL certificate, defaults to 'Undefined'
* **organization** - The organization for the SSL certificate, defaults to 'Undefined'
* **common_name** - The common name for the SSL certificate, defaults to 'Undefined'
* **validity** - The validity length for the SSL certificate, defaults to 365 days
* **password** - The password used to encrypt the private key, if none is provided it will be prompted for

**Returns:**
* **password** - The password used to encrypt the private key
						