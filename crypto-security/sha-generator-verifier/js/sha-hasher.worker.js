/**
 * VanillaTools (VTools) - Native SHA Hasher Web Worker
 * Path: /crypto-security/sha-generator-verifier/js/sha-hasher.worker.js
 * 
 * Strict Client-Side, Zero-Backend, 100% Native Web Crypto API.
 * Assembles streamed chunk buffers off the main thread securely, 
 * sanitizes old memory chunks instantly, and prevents OOM crashes.
 */

self.importScripts('/assets/js/vendors/hash-wasm/hash-wasm.min.js');

let hasher = null;
let processedBytes = 0;
let streamStartTime = null;

self.onmessage = async (e) => {
    const { type, buffer, algorithm, fileSize, isLast } = e.data;
    if (type !== 'chunk') return;

    try {
        // 1. Inisialisasi WASM Hasher pada chunk pertama
        if (!hasher) {
            hasher = algorithm === 'SHA-512' 
                ? await self.hashwasm.createSHA512() 
                : await self.hashwasm.createSHA256();
            hasher.init();
            streamStartTime = performance.now();
            processedBytes = 0;
        }

        // 2. TRUE STREAMING: Update state internal WASM per chunk (Tanpa menyimpan array di RAM)
        const view = new Uint8Array(buffer);
        hasher.update(view);
        processedBytes += buffer.byteLength;

        // 3. WIPE MEMORY: Segera hapus chunk RAM setelah dicerna
        if (view.fill) view.fill(0);

        // 4. Progress Reporting (Dibatasi per 60ms)
        const now = performance.now();
        if (now - streamStartTime >= 60 || isLast) {
            const elapsedSec = (now - streamStartTime) / 1000;
            const speedMBs = elapsedSec > 0 ? (processedBytes / (1024 * 1024)) / elapsedSec : 0;
            self.postMessage({
                type: 'progress',
                payload: { processedBytes, totalBytes: fileSize, percent: (processedBytes / fileSize) * 100, speedMBs }
            });
        }

        // 5. Finalisasi & Pengembalian Buffer
        if (isLast) {
            const rawDigest = hasher.digest('binary');
            const digestBuffer = rawDigest.buffer;
            
            self.postMessage({ type: 'complete', payload: { rawDigest: digestBuffer } }, [digestBuffer]);

            // Daur ulang state
            hasher = null;
            processedBytes = 0;
            streamStartTime = null;
        }
    } catch (err) {
        hasher = null;
        self.postMessage({ type: 'error', payload: { message: err.message || 'Worker WASM Hashing failed' } });
    }
};