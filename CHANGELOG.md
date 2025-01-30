# Version 2.0.0

- OpenSSL 3.x Provider support for RSA operations

# Version 1.4.1

- Key list in service is managed using an LRU cache, with the list size being configurable 
- Distro packaging support includes Azure Linux 3.0 for both ARM and x86 architectures, as well as Ubuntu 24.04 
- Bug fixes

# Version 1.4.0

- Bug fixes
- Introduces a .NET wrapper for Azure Linux 2.0, including methods for importing PFX files and validating Key IDs
- Handle a "magic" field in RSA private keys
- Adds conditional dependencies to the CMake packaging based on the detected Ubuntu version

# Version 1.2.2
- TPM Runtime Protection: Added support in protecting keys stored in TPM.
- OpenSSL 3.1.4 support
- Bug fixes

# Version 1.2.1

- Ubuntu 22.04 package support
- Minor bug fixes

# Version 1.2.0

- Introduce Symmetric Key support: The symmetric key is imported to KMPP client and encrypted by the KMPP service. This result producing encrypted data. The encrypted key from the import is used in symmetric key cryptographic operations (encryption / decryption).
- Support ARM64
- Support disable certificate chain validation during the import of the private key into KMPP
- Using SymCrypt in the KMPP service: The default library for cryptographic operations has been changed from OpenSSL to SymCrypt. However, when SymCrypt doesn't support certain RSA parameters, in some cases KMPP falls back to OpenSSL where feasible. Additionally, OpenSSL is used for backward compatibility.
- Support Key Usage: This feature limits the use of imported private keys by utilizing key usage flags. These flags provide granular control over whether a key can be used for encryption, signing, or both.
- TPM Machine Secret Protection: Protects private keys with TPM at rest. 
- Bug fixes

# Version 1.1.8

- Telemetry support
- Bug fixes
