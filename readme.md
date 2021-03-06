# TPM Util

Simple tools for using a TPM for encryption.

The TPM spec is quite a bit more complicated than it really needs to be.
So this is half utility and half demonstration of how to get simple common-sense
features out of a TPM.

## tpm
* `init`: Sets `PCR[16]` to a random number, used for a session id, panics if already initialized
* `sess`: Reads the session id from `PCR[16]`, panics if not initialized
* `id <arg>`: Provides the hash of arg + the TPM's root public key, useful as a device ID
* `mksec`: Generates a 128 bit random value and encrypts it using the TPM, locked to PCR 0-15 except 1.
  Writes result to stdout as base64.
* `decryptsec <file> <arg>`: Attempts to decrypt a file containing the result of `mksec`, if decryption
  is successful, result is hashed with `<arg>` and result is placed in `PCR[10]`. PCRs 0-15 must be same
  as they were during `mksec` (except `PCR[1]` which can be different).
* `sec <arg>`: Hashes value of `PCR[10]` with `<arg>` to provide a secret derived from `decryptsec`.
* `<no arguments>`: Prints the values of all PCRs

## macserver
* `import <file>`: Reads file as a secret key to import for creating HMACs, this key is encrypted to the
TPM with no specific PCRs required, resulting encrypted value (base64) is written to stdout. After this
secret value has been imported, it never leaves the TPM in unencrypted form.
* `serv <file> <bind>`: Binds address/port specified as `<bind>`, loads MAC from `<file>` into TPM and
begins an http server.

### Endpoints
* `/hmac`
  * POST body must be less than or equal to 128 bytes in length
  * Result: The hmac of the secret value added with `import` plus the posted value.

### Example

```
# echo '7aac64aabaecd3c63e2cfcda27ce92091ffcf4d858eacdbb215bcac116ac3838' | \
    ./bin/macserver import - > ~/tpm_test_secret.hex
# ./bin/macserver serv ~/tpm_test_secret.hex localhost:9999

## In another window
# curl -s -X POST -d 'hello world' localhost:9999/hmac | hexdump
0000000 978f fe5c f84a 314d 7b9d 38ee 3587 8a81
0000010 4964 60cf b10e 70d9 a8a5 2e68 a5e8 1139
0000020
```