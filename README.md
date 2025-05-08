# Introduction
Key Management and Protection Platform (KMPP) is a platform use to protect and isolate keys in Linux-based environments. <br>
Key Isolation technique allows to host the key material securely – protected and separated (isolated) and perform Private Keys cryptographic operations so that the key material is never exposed to the calling app or other apps on the same system. <br>
By doing so, the Key Isolation technique decreases the likelihood of Key Exfiltration by an attacker. Its promise is to make sure that key on a system cannot be exported or taken off the machine it was created on or imported into

## History
The platform was started in 2019 targeting keys protection on Azure Boost and evolved to an OSS project, protecting cryptographic keys in Azure services 

## Prerequisites
OpenSSL	version 1.1.1 <br>
SymCrypt - Microsoft core cryptographic library <br>
TSS - TPM2 Software Stack (already installed in Mariner 2.0) 

## Building  
The best way to get started with building the KMPP after the repo cloning, is by running restore.sh that will install prerequisites packaged needed for building the code, then following these instructions:
```
sudo sh restore.sh
mkdir build
cd build
cmake ..
make
```

## Installing 
Once built, install all required libraires for running the application:
```
sudo sh ../scripts/preinst  
sudo make install  
sudo sh ../scripts/postinst 
```

For general purpose Linux machines when OpenSSL version is 3.x and above, the default KMPP provider configuration will be
automatically set as part of the postinst script unless explicitly disabled by the admin by creating an empty file as follows:

```
touch /etc/kmpp/disableDefaultProvider 

```
This file indicates the installation of KMPP without default configuration.  
It is the admin's responsibility to create and remove the file.<br><br>

In the default case, KMPP is configured as the default provider during the installation process 
when changes are made to the openssl.cnf file, with a backup file created for use in case of uninstallation. <br>  
NOTE: This backup file should not be removed or edited. <br>

In order to use the KMPP provider as the default provider, follow these steps:<br>  
1. Enable the KMPP provider in the config.cnf file located at /var/opt/msft/ap/data/kmpp/config.cnf.<br>  
   A template can be found at /usr/share/kmpp/. <br> 
2. Add the applications that the KMPP default provider will support in a file located at /var/opt/msft/ap/data/kmpp/kmpp_apps.json.<br>
   The file should have the following structure:

 ```
{
    "allowed_apps": [
        "app1",
        "app2",
        "app3"
    ]
} 
```

If all applications should be supported, the admin can simply write "ALL".

## Uninstalling 
In case of uninstalling KMPP, the configuration will be removed by the prerm script, 
based on the backup file created during installation.


## Versioning 
KMPP uses the version scheme defined by the
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) specification. This means:

- Major version changes introduce ABI and/or API breaking changes (including behavior changes)
- Minor version changes introduce backwards compatible additional functionality or improvements, and/or bug fixes
- Patch version changes introduce backwards compatible bug fixes

The initial open source release started at version 2 for compatibility with our previous
internal versioning scheme.

## Notes
Detailed service information can be fount at https://aka.ms/kmpp <br>

KMPP supports the following ecc curves:<br>
prime192v1 - Only if is being supported by the OpenSSL version on the client side (mariner2 image has openssl version that does not support this curve) <br>
prime256v1 <br>
secp224r1 <br>
secp384r1 <br>
secp521r1 <br>
