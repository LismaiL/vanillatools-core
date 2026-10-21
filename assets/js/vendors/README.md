# Third-Party Local Vendors

To adhere to VanillaTools' **Zero External CDN Policy** and **Strict Content Security Policy (CSP)**, third-party libraries are compiled and hosted locally in production under this path.

Third-party binaries are excluded from this core repository to keep the codebase lightweight and focused on original architectural logic.

## Vendor Dependencies:

- **hash-wasm** (MIT License)  
  *Official Repo:* https://github.com/Daninet/hash-wasm
  *Usage:* WebAssembly primitives for streaming SHA hashes, Argon2, and Bcrypt.

- **big.js** (MIT License)  
  *Official Repo:* https://github.com/MikeMcl/big.js
  *Usage:* Arbitrary-precision decimal arithmetic for highly accurate client-side math operations.

- **lz-string** (MIT License)  
  *Official Repo:* https://github.com/pieroxy/lz-string
  *Usage:* Fast, client-side LZ-based data compression and decompression algorithms.