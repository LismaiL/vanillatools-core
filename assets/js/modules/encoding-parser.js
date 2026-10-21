/**
 * VanillaTools (VTools) - EncodingParser Module
 * Category: /crypto-security/ & Shared Modules
 * 
 * Strict Client-Side, Zero-Backend, High-Performance ES6 Class.
 * Provides parsing for UTF-8, Hexadecimal, and Base64 (Standard & URL-safe),
 * safe zero-fill memory wiping, and constant-time comparisons for timing-attack resistance.
 */

export class EncodingParser {
    static #utf8Encoder = new TextEncoder();
    static #utf8Decoder = new TextDecoder('utf-8', { fatal: true });
    
    // Hex lookup table for high-performance encoding
    static #hexTable = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
    static #hexTableUpper = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0').toUpperCase());

    /**
     * Converts a string, ArrayBuffer, TypedArray, or DataView to a Uint8Array.
     * @param {Uint8Array|ArrayBuffer|ArrayBufferView} input
     * @returns {Uint8Array}
     */
    static ensureUint8Array(input) {
        if (input instanceof Uint8Array) {
            return input;
        }
        if (input instanceof ArrayBuffer) {
            return new Uint8Array(input);
        }
        if (ArrayBuffer.isView(input)) {
            return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
        }
        throw new TypeError('Expected Uint8Array, ArrayBuffer, or ArrayBufferView');
    }

    /* ----------------------------------------------------
       1. UTF-8 PARSING & SERIALIZATION
       ---------------------------------------------------- */

    /**
     * Encodes a UTF-8 string into a Uint8Array.
     * @param {string} str
     * @returns {Uint8Array}
     */
    static utf8ToBytes(str) {
        if (typeof str !== 'string') {
            throw new TypeError('Input must be a string');
        }
        return this.#utf8Encoder.encode(str);
    }

    /**
     * Decodes a Uint8Array or ArrayBuffer into a UTF-8 string.
     * Throws on invalid UTF-8 byte sequences.
     * @param {Uint8Array|ArrayBuffer|ArrayBufferView} bytes
     * @returns {string}
     */
    static bytesToUtf8(bytes) {
        const u8 = this.ensureUint8Array(bytes);
        try {
            return this.#utf8Decoder.decode(u8);
        } catch (err) {
            throw new Error(`Invalid UTF-8 sequence: ${err.message}`);
        }
    }

    /* ----------------------------------------------------
       2. HEXADECIMAL PARSING & SERIALIZATION
       ---------------------------------------------------- */

    /**
     * Parses a hexadecimal string into a Uint8Array.
     * Handles optional whitespace, prefixes (0x), and validates character boundaries.
     * @param {string} hexStr
     * @returns {Uint8Array}
     */
    static hexToBytes(hexStr) {
        if (typeof hexStr !== 'string') {
            throw new TypeError('Hex input must be a string');
        }

        // Clean common prefixes (0x) and whitespace/colons
        const cleaned = hexStr.replace(/^0x/i, '').replace(/[\s:]+/g, '');
        
        if (cleaned.length === 0) {
            return new Uint8Array(0);
        }

        if (cleaned.length % 2 !== 0) {
            throw new Error('Hexadecimal string must have an even length');
        }

        if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
            throw new Error('Invalid hexadecimal characters detected');
        }

        const len = cleaned.length / 2;
        const bytes = new Uint8Array(len);

        for (let i = 0; i < len; i++) {
            bytes[i] = parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
        }

        return bytes;
    }

    /**
     * Serializes a Uint8Array or ArrayBuffer into a hexadecimal string.
     * @param {Uint8Array|ArrayBuffer|ArrayBufferView} bytes
     * @param {Object} [options]
     * @param {boolean} [options.uppercase=false]
     * @returns {string}
     */
    static bytesToHex(bytes, { uppercase = false } = {}) {
        const u8 = this.ensureUint8Array(bytes);
        const table = uppercase ? this.#hexTableUpper : this.#hexTable;
        let out = '';
        const len = u8.length;
        
        for (let i = 0; i < len; i++) {
            out += table[u8[i]];
        }
        
        return out;
    }

    /* ----------------------------------------------------
       3. BASE64 PARSING & SERIALIZATION
       ---------------------------------------------------- */

    /**
     * Parses a Base64 string (Standard or URL-Safe) into a Uint8Array.
     * Automatically handles missing padding and URL-safe characters (- and _).
     * @param {string} base64Str
     * @returns {Uint8Array}
     */
    static base64ToBytes(base64Str) {
        if (typeof base64Str !== 'string') {
            throw new TypeError('Base64 input must be a string');
        }

        // Strip whitespace and replace URL-safe chars with standard Base64
        let cleaned = base64Str.trim().replace(/\s+/g, '')
            .replace(/-/g, '+')
            .replace(/_/g, '/');

        if (cleaned.length === 0) {
            return new Uint8Array(0);
        }

        // Auto-pad if necessary
        const padLen = (4 - (cleaned.length % 4)) % 4;
        cleaned += '='.repeat(padLen);

        // Validate format
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned)) {
            throw new Error('Invalid Base64 character sequence');
        }

        try {
            const binaryString = atob(cleaned);
            const len = binaryString.length;
            const bytes = new Uint8Array(len);
            
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            return bytes;
        } catch (err) {
            throw new Error(`Failed to decode Base64: ${err.message}`);
        }
    }

    /**
     * Serializes a Uint8Array or ArrayBuffer into a Base64 string.
     * Chunked to prevent call stack overflow with large byte buffers.
     * @param {Uint8Array|ArrayBuffer|ArrayBufferView} bytes
     * @param {Object} [options]
     * @param {boolean} [options.urlSafe=false]
     * @returns {string}
     */
    static bytesToBase64(bytes, { urlSafe = false } = {}) {
        const u8 = this.ensureUint8Array(bytes);
        const len = u8.length;
        const chunkSize = 8192;
        let binaryString = '';

        for (let i = 0; i < len; i += chunkSize) {
            const sub = u8.subarray(i, Math.min(i + chunkSize, len));
            binaryString += String.fromCharCode.apply(null, sub);
        }

        let base64 = btoa(binaryString);

        if (urlSafe) {
            base64 = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }

        return base64;
    }

    /* ----------------------------------------------------
       4. UNIFIED PARSER & FORMATTER (Convenience APIs)
       ---------------------------------------------------- */

    /**
     * Universal input parser converting any standard format to Uint8Array.
     * @param {string|Uint8Array} input
     * @param {'utf8'|'hex'|'base64'} [format='utf8']
     * @returns {Uint8Array}
     */
    static parse(input, format = 'utf8') {
        if (input instanceof Uint8Array) {
            return input;
        }
        switch (format.toLowerCase()) {
            case 'utf8':
            case 'utf-8':
            case 'text':
                return this.utf8ToBytes(input);
            case 'hex':
            case 'hexadecimal':
                return this.hexToBytes(input);
            case 'base64':
            case 'b64':
                return this.base64ToBytes(input);
            default:
                throw new Error(`Unsupported input encoding format: ${format}`);
        }
    }

    /**
     * Universal byte formatter converting Uint8Array to specified format.
     * @param {Uint8Array|ArrayBuffer} bytes
     * @param {'utf8'|'hex'|'base64'} [format='hex']
     * @param {Object} [options]
     * @returns {string}
     */
    static format(bytes, format = 'hex', options = {}) {
        switch (format.toLowerCase()) {
            case 'utf8':
            case 'utf-8':
            case 'text':
                return this.bytesToUtf8(bytes);
            case 'hex':
            case 'hexadecimal':
                return this.bytesToHex(bytes, options);
            case 'base64':
            case 'b64':
                return this.bytesToBase64(bytes, options);
            default:
                throw new Error(`Unsupported output format: ${format}`);
        }
    }

    /* ----------------------------------------------------
       5. MEMORY HYGIENE: ZERO-FILL WIPING
       ---------------------------------------------------- */

    /**
     * Securely clears sensitive cryptographic data by filling memory with zeros.
     * Works on Uint8Array, TypedArrays, ArrayBuffers, and DataViews.
     * @param {Uint8Array|ArrayBuffer|ArrayBufferView} target
     * @returns {boolean} True if successfully wiped
     */
    static wipe(target) {
        if (!target) return false;

        try {
            if (target instanceof Uint8Array || ArrayBuffer.isView(target)) {
                new Uint8Array(target.buffer, target.byteOffset, target.byteLength).fill(0);
                return true;
            }
            if (target instanceof ArrayBuffer) {
                new Uint8Array(target).fill(0);
                return true;
            }
        } catch (_) {
            return false;
        }

        return false;
    }

    /* ----------------------------------------------------
       6. CRYPTOGRAPHIC UTILITY: CONSTANT-TIME COMPARISON
       ---------------------------------------------------- */

    /**
     * Performs a constant-time equality check between two byte arrays or strings.
     * Prevents side-channel timing attacks when validating signatures, hashes, or tokens.
     * @param {Uint8Array|string} a
     * @param {Uint8Array|string} b
     * @returns {boolean}
     */
    static constantTimeEqual(a, b) {
        const bytesA = typeof a === 'string' ? this.utf8ToBytes(a) : this.ensureUint8Array(a);
        const bytesB = typeof b === 'string' ? this.utf8ToBytes(b) : this.ensureUint8Array(b);

        // Constant-time length discrepancy flag
        const lenA = bytesA.length;
        const lenB = bytesB.length;
        let mismatch = lenA ^ lenB;

        // Compare up to lenA; if lengths differ, we still iterate through bytesA
        for (let i = 0; i < lenA; i++) {
            const byteB = i < lenB ? bytesB[i] : 0;
            mismatch |= bytesA[i] ^ byteB;
        }

        return mismatch === 0;
    }

    /**
     * Alias for constantTimeEqual.
     */
    static timingSafeEqual(a, b) {
        return this.constantTimeEqual(a, b);
    }

    /**
     * Alias for constantTimeEqual.
     */
    static constantTimeCompare(a, b) {
        return this.constantTimeEqual(a, b);
    }
}

export default EncodingParser;
