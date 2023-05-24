# ficrypt

ficrypt is a command-line tool for encrypting and decrypting files using the [AES-128](https://www.nist.gov/publications/advanced-encryption-standard-aes) bit algorithm. It provides a simple interface to encrypt or decrypt a file with a user-defined encryption key.

**Disclaimer: This encryption tool was developed as an independent endeavor. It may not provide the same level of security or reliability as more established encryption tools such as OpenSSL. Use this tool at your own risk. The authors and maintainers of this crate are not responsible for any potential damage caused by its use.**

## Usage

The general usage format is as follows:

```bash
ficyrpt [-d] <FILE> <OUTPUT-FILE>
```

- `<FILE>`: The path to the file to be encrypted or decrypted.
- `<OUTPUT-FILE>`: The path to the output file after encryption or decryption.
- `-d`: Optional flag indicating decryption. If present, the tool will decrypt the file instead of encrypting it.

**Note:** When the program is run, it will prompt to enter the encryption key. Make sure to provide a strong and secure encryption key.

### Examples

1. Encrypting a file:

```bash
$ ficrypt file.txt file.dat
Enter the encryption key: ********
```

2. Decrypting a file:

```bash
$ ficrypt -d file.dat file.txt
Enter the encryption key: ********
```

## Installation

To use the tool, you need to have Rust installed on your system. If you don't have it installed, you can get it from the official [Rust website](https://www.rust-lang.org/tools/install).

Once you have Rust installed, you can build the tool using Cargo, the package manager and build system for Rust:

 1. Clone the GitHub repository to your local machine:

```bash
git clone https://github.com/gustavocmaciel/ficrypt.git
cd ficrypt
```

2. Build the project using Cargo:

```bash
cargo build --release
```

The binary executable will be generated in the `target/release` directory. You can either add this directory to your system's PATH or use the binary directly from that location.

Alternatively, you can install it globally using:

```bash
cargo install --path .
```

This will install the tool to your system, allowing you to use it from anywhere.

## Contributing

Contributions are welcome! If you find any issues, have suggestions for improvements, or would like to add new features, please feel free to open an issue or submit a pull request.

When contributing, please follow the existing code style, write clear commit messages, and provide appropriate test coverage for your changes.

## Notes

- The ficrypt tool has been primarily tested and developed on Unix-like systems, such as Linux and macOS. While it may work on other platforms, there could be potential issues or unexpected behavior on non-Unix systems.
- The tool currently supports only the AES-128 bit algorithm. 
- The tool has been tested with various file types and sizes, but it may have performance limitations or encounter issues with extremely large files or unique file formats.
- As with any encryption tool, the security of the encrypted files depends not only on the algorithm but also on the strength and confidentiality of the encryption key chosen by the user. It is recommended to use strong and unique encryption keys.
- The ficrypt tool does not provide additional security measures, such as key management or secure key exchange protocols. It assumes that the user securely manages and exchanges encryption keys outside the scope of the tool.

Please keep these in mind while using ficrypt.

## License

This project is licensed under the [MIT License](LICENSE).
