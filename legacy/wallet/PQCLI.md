# BlackSilk Wallet: Post-Quantum CLI Usage

## Post-Quantum (PQ) Signature Support

BlackSilk wallet supports NIST-finalist post-quantum signature schemes:
- Dilithium2
- Falcon512

All PQ key management, signing, and verification is production-grade and uses only NIST-finalist algorithms. Legacy/experimental PQC code has been removed.

## CLI Commands for PQ Key Management and Signatures

### Generate PQ Keypair
```
wallet quantum keygen --alg <dilithium2|falcon512|all> [--out <prefix>]
```
- Generates a PQ keypair for the selected algorithm(s).
- Example: `wallet quantum keygen --alg dilithium2 --out mykey`
- Output: `mykey_dilithium2_pk.bin`, `mykey_dilithium2_sk.bin`

### Sign a Message
```
wallet quantum sign --alg <dilithium2|falcon512> --key <private_key_file> --message <message_file> [--out <signature_file>]
```
- Signs the message file with the selected PQ private key.
- Example: `wallet quantum sign --alg falcon512 --key mykey_falcon512_sk.bin --message msg.txt --out sig.bin`

### Verify a Signature
```
wallet quantum verify --alg <dilithium2|falcon512> --key <public_key_file> --message <message_file> --signature <signature_file>
```
- Verifies a PQ signature.
- Example: `wallet quantum verify --alg dilithium2 --key mykey_dilithium2_pk.bin --message msg.txt --signature sig.bin`

### Export a PQ Key
```
wallet quantum export --alg <dilithium2|falcon512> --type <pub|priv> --out <output_file>
```
- Exports a PQ public or private key to a file.

### Show PQ Public Key
```
wallet quantum show-pubkey --alg <dilithium2|falcon512>
```
- Prints the PQ public key in hex (for address or migration).

## Security Notes
- Always protect your private keys. Never share them.
- PQ keys are not compatible with legacy/experimental schemes.
- For migration, use both Ed25519 and PQ keys as needed.

## Example Workflow
1. Generate keys: `wallet quantum keygen --alg all --out alice`
2. Sign: `wallet quantum sign --alg dilithium2 --key alice_dilithium2_sk.bin --message tx.bin --out sig.bin`
3. Verify: `wallet quantum verify --alg dilithium2 --key alice_dilithium2_pk.bin --message tx.bin --signature sig.bin`

---
For more, run `wallet quantum --help` or see the main README.
