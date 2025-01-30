# Introduction

The Key Material Protection Platform (KMPP) is designed to safeguard TLS keys in Linux-based environments. It utilizes a Key Isolation technique, which hosts the key material in an isolated space and performs cryptographic operations on behalf of the calling application. This ensures that the key material is not exposed to the calling application or other applications on the same system. By doing so, it significantly reduces the risk of key exfiltration by attackers. The primary objective of KMPP is to ensure that key material cannot be exported or removed from the machine where it was created or imported.

## Prerequisites
- OpenSSL	version 1.1.1 or 3.0.2 <br>
- SymCrypt - Microsoft core cryptographic library <br>
- TSS - TPM2 Software Stack (already installed in Azure Linux 2.0) 

## Supported Linux Operating Systems
- Azure Linux 2.0 <br>
- Ubuntu 20.04 <br>
- Ubuntu 22.04 <br> 

## Building

The easiest way to get started building KMPP is to use the provided Bash script, `scripts/build.sh`. This script automates the entire process, including installing dependencies, configuring the project with CMake, and building it.

You can run the script with the `--help` argument to get detailed information about available options and usage:

```bash
./scripts/build.sh --help
```

### Example Usage:

1. **Basic Build:**
   Run the script without any arguments to perform a standard build:
   ```bash
   ./scripts/build.sh
   ```

2. **Custom Configuration:**
   Use the script to apply specific configuration options. For instance, to enable debug features during the build process, modify the configuration using the         following commands:
   ```bash
   cmake -S . -B build -DKMPP_DEBUG=ON
   cmake --build build
   ```
   Then, run the build script:
   ```bash
   ./scripts/build.sh
   ```

### Notes:
- Ensure that the `scripts/build.sh` script is executable. If it's not, you can make it executable using:
  ```bash
  chmod +x scripts/build.sh
  ```
- The script takes care of most dependencies and configuration steps, making it easier for users to build the project with minimal setup.

---


## Testing

### Automated Testing

1. **Run Predefined Tests**:
   The `scripts/build.sh` script automatically builds and runs the example program (`kmppexample`) as part of its execution. If the script completes without errors, it indicates that the example ran successfully and the core functionality of KMPP is verified.

2. **Check Logs**:
   Review the output logs from the script execution. These logs will indicate whether the example executed correctly and provide any relevant information about issues or errors encountered. A result of 1 in the logs indicates success.


## Versioning 
KMPP uses the version scheme defined by the
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) specification. This means:

- Major version changes introduce ABI and/or API breaking changes (including behavior changes)
- Minor version changes introduce backwards compatible additional functionality or improvements, and/or bug fixes
- Patch version changes introduce backwards compatible bug fixes

The initial open source release started at version 2 for compatibility with our previous
internal versioning scheme.

## Notes
KMPP supports the following ecc curves:<br>
- prime192v1 : Only if is being supported by the OpenSSL version on the client side (Azure Linux 2.0 image has openssl version that does not support this curve) <br>
- prime256v1 <br>
- secp224r1 <br>
- secp384r1 <br>
- secp521r1 <br>
  
#### AppArmor
If AppArmor is enabled, you need to define and install profiles so the KMPP Service, KMPP CTRL Service, and the client application will be able to communicate. You also need to use the client profile in your YAML.

## Contribute
We love to receive comments and suggestions. Unfortunately we cannot accept external code contributions except in specific circumstances from vetted partners with whom we have a pre-arranged agreement. <br> <br>
This project has adopted the Microsoft Open Source Code of Conduct. For more information see the Code of Conduct FAQ or contact opencode@microsoft.com with any additional questions or comments.


Trademarks This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
