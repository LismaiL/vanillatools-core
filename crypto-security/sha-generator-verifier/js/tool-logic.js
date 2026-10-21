/**
 * VanillaTools (VTools) - SHA-256 & SHA-512 Generator & Verifier Logic
 * Category: /crypto-security/sha-generator-verifier/
 * 
 * Strict Client-Side, Zero-Backend, 100% Vanilla JS (ES6+).
 * High-performance cryptographic hashing via native Web Crypto API and
 * off-thread Web Worker streaming with transferable ArrayBuffers for large files.
 */

import { EncodingParser } from '/assets/js/modules/encoding-parser.js';

class ShaToolEngine {
    #currentCancellation = null;
    #lastComputedBytes = null;

    /**
     * Computes SHA hash for in-memory text payload using native Web Crypto API.
     * @param {string} text
     * @param {'SHA-256'|'SHA-512'} algorithm
     * @param {'utf-8'|'hex'|'base64'} inputEncoding
     * @returns {Promise<{ bytes: Uint8Array, elapsedMs: number }>}
     */
    async hashText(text, algorithm = 'SHA-256', inputEncoding = 'utf-8') {
        const start = performance.now();
        const inputBytes = EncodingParser.parse(text, inputEncoding);

        try {
            const buffer = await window.crypto.subtle.digest(algorithm, inputBytes);
            const digestBytes = new Uint8Array(buffer);
            const elapsedMs = performance.now() - start;

            this.#lastComputedBytes = digestBytes;
            return { bytes: digestBytes, elapsedMs };
        } finally {
            // Segera timpa buffer input sensitif dengan nol setelah digest selesai
            EncodingParser.wipe(inputBytes);
        }
    }

    /**
     * Computes SHA hash for a file using incremental slice chunking.
     * Uses pure ES module Web Worker to prevent main thread blocking and memory bloat.
     * @param {File} file
     * @param {'SHA-256'|'SHA-512'} algorithm
     * @param {number} chunkSize
     * @param {Function} onProgress
     * @returns {Promise<{ bytes: Uint8Array, elapsedMs: number }>}
     */
    async hashFileStream(file, algorithm = 'SHA-256', chunkSize = 8388608, onProgress = null) {
        // Handle empty file edge case secara native
        if (file.size === 0) {
            const emptyBuffer = await window.crypto.subtle.digest(algorithm, new Uint8Array(0));
            const digestBytes = new Uint8Array(emptyBuffer);
            this.#lastComputedBytes = digestBytes;
            return { bytes: digestBytes, elapsedMs: 0 };
        }

        const cancelToken = { isCancelled: false };
        this.#currentCancellation = cancelToken;
        const startTime = performance.now();
        let lastReportTime = startTime;

        // Gunakan Web Worker terisolasi lokal dari direktori sektoral tool
        const worker = new Worker('/crypto-security/sha-generator-verifier/js/sha-hasher.worker.js');

        return new Promise((resolve, reject) => {
            worker.onmessage = (e) => {
                const { type, payload } = e.data;

                if (type === 'progress') {
                    const now = performance.now();
                    if (onProgress && (now - lastReportTime >= 60 || payload.percent === 100)) {
                        onProgress(payload);
                        lastReportTime = now;
                    }
                } else if (type === 'complete') {
                    const digestBytes = new Uint8Array(payload.rawDigest);
                    this.#lastComputedBytes = digestBytes;
                    worker.terminate(); // Terminasi langsung setelah selesai untuk GC instan
                    this.#currentCancellation = null;
                    resolve({ bytes: digestBytes, elapsedMs: performance.now() - startTime });
                } else if (type === 'error') {
                    worker.terminate();
                    this.#currentCancellation = null;
                    reject(new Error(payload.message));
                }
            };

            worker.onerror = (err) => {
                worker.terminate();
                this.#currentCancellation = null;
                reject(err);
            };

            // Mulai streaming chunk ke worker via transferable objects
            (async () => {
                let offset = 0;
                const fileSize = file.size;

                while (offset < fileSize) {
                    if (cancelToken.isCancelled) {
                        worker.terminate();
                        this.#currentCancellation = null;
                        reject(new DOMException('File hashing cancelled by user', 'AbortError'));
                        return;
                    }

                    const currentChunkEnd = Math.min(offset + chunkSize, fileSize);
                    const blobSlice = file.slice(offset, currentChunkEnd);
                    const arrayBuffer = await blobSlice.arrayBuffer();

                    // Transfer ArrayBuffer kepemilikan ke worker (Zero-Copy) untuk melegakan memori utama
                    worker.postMessage({
                        type: 'chunk',
                        buffer: arrayBuffer,
                        algorithm,
                        offset,
                        fileSize,
                        isLast: currentChunkEnd >= fileSize
                    }, [arrayBuffer]);

                    offset = currentChunkEnd;
                    await new Promise(r => setTimeout(r, 0)); // Yield thread
                }
            })().catch(err => {
                worker.terminate();
                this.#currentCancellation = null;
                reject(err);
            });
        });
    }

    cancelCurrentOperation() {
        if (this.#currentCancellation) {
            this.#currentCancellation.isCancelled = true;
            this.#currentCancellation = null;
        }
    }

    wipeMemory() {
        if (this.#lastComputedBytes) {
            EncodingParser.wipe(this.#lastComputedBytes);
            this.#lastComputedBytes = null;
            return true;
        }
        return false;
    }

    getLastDigestBytes() {
        return this.#lastComputedBytes;
    }
}

/* ----------------------------------------------------
   UI CONTROLLER & DOM INTEGRATION
   ---------------------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
    const engine = new ShaToolEngine();

    // DOM Elements - Mode Switching
    const tabText = document.getElementById('tab-text-mode');
    const tabFile = document.getElementById('tab-file-mode');
    const containerText = document.getElementById('text-input-container');
    const containerFile = document.getElementById('file-input-container');
    const settingTextEncoding = document.getElementById('setting-text-encoding');
    const settingChunkSize = document.getElementById('setting-chunk-size');

    // DOM Elements - Inputs
    const textInput = document.getElementById('tool-input');
    const textCounter = document.getElementById('text-counter');
    const dropZone = document.getElementById('drop-zone');
    const filePicker = document.getElementById('file-picker');
    const fileInfoCard = document.getElementById('file-info-card');
    const fileNameSpan = document.getElementById('file-name');
    const fileMetaSpan = document.getElementById('file-meta');
    const btnRemoveFile = document.getElementById('btn-remove-file');

    // DOM Elements - Progress
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('stream-progress');
    const progressPercent = document.getElementById('progress-percent');
    const progressSpeed = document.getElementById('progress-speed');
    const progressStatus = document.getElementById('progress-status');
    const btnCancelStream = document.getElementById('btn-cancel-stream');

    // DOM Elements - Verification
    const targetHashInput = document.getElementById('target-hash');
    const verifyBadge = document.getElementById('verify-badge');
    const verifyText = document.getElementById('verify-text');

    // DOM Elements - Output & Actions
    const toolOutput = document.getElementById('tool-output');
    const btnProcess = document.getElementById('btn-process');
    const btnClear = document.getElementById('btn-clear');
    const btnCopy = document.getElementById('btn-copy');
    const btnWipe = document.getElementById('btn-wipe');
    const execAlgoSpan = document.getElementById('exec-algorithm');
    const execTimeSpan = document.getElementById('exec-time');

    // DOM Elements - Settings & Algorithm Selection
    const algoRadios = document.querySelectorAll('input[name="algorithm"]');
    const formatSelect = document.getElementById('format-select');
    const encodingSelect = document.getElementById('encoding-select');
    const chunkSizeSelect = document.getElementById('chunk-size-select');
    const autoProcessToggle = document.getElementById('auto-process-toggle');

    // Internal State
    let currentMode = 'text'; // 'text' | 'file'
    let selectedFile = null;
    let isProcessing = false;
    let currentDigestBytes = null;

    /* ----------------------------------------------------
       1. HELPER FORMATTERS & ACCESSORS
       ---------------------------------------------------- */
    const getSelectedAlgorithm = () => {
        const checked = document.querySelector('input[name="algorithm"]:checked');
        return checked ? checked.value : 'SHA-256';
    };

    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const formatDigestOutput = (bytes) => {
        if (!bytes || bytes.length === 0) return '';
        const format = formatSelect.value;
        switch (format) {
            case 'hex-upper':
                return EncodingParser.bytesToHex(bytes, { uppercase: true });
            case 'base64':
                return EncodingParser.bytesToBase64(bytes, { urlSafe: false });
            case 'base64url':
                return EncodingParser.bytesToBase64(bytes, { urlSafe: true });
            case 'hex-lower':
            default:
                return EncodingParser.bytesToHex(bytes, { uppercase: false });
        }
    };

    /* ----------------------------------------------------
       2. REAL-TIME CONSTANT-TIME VERIFICATION
       ---------------------------------------------------- */
    const updateVerificationStatus = () => {
        const expected = targetHashInput.value.trim();
        const currentOutput = toolOutput.value.trim();

        verifyBadge.classList.remove('status-match', 'status-mismatch', 'status-neutral');
        targetHashInput.classList.remove('status-match', 'status-mismatch');

        if (!expected) {
            verifyBadge.classList.add('status-neutral');
            verifyBadge.firstElementChild.textContent = '⚪';
            verifyText.textContent = 'Awaiting checksum input for comparison';
            return;
        }

        if (!currentOutput) {
            verifyBadge.classList.add('status-neutral');
            verifyBadge.firstElementChild.textContent = '⚪';
            verifyText.textContent = 'Generate a hash first to compare';
            return;
        }

        let isMatch = false;
        const isHexFormat = formatSelect.value.startsWith('hex');

        if (isHexFormat) {
            // Case-insensitive constant-time comparison for hex checksums
            try {
                const expectedBytes = EncodingParser.hexToBytes(expected);
                const currentBytes = EncodingParser.hexToBytes(currentOutput);
                isMatch = EncodingParser.constantTimeCompare(expectedBytes, currentBytes);
            } catch (_) {
                // If expected is not valid hex of equal length, fall back to string comparison
                isMatch = EncodingParser.constantTimeCompare(expected.toLowerCase(), currentOutput.toLowerCase());
            }
        } else {
            // Strict constant-time comparison for Base64 / Base64URL
            isMatch = EncodingParser.constantTimeCompare(expected, currentOutput);
        }

        if (isMatch) {
            verifyBadge.classList.add('status-match');
            targetHashInput.classList.add('status-match');
            verifyBadge.firstElementChild.textContent = '✅';
            verifyText.textContent = 'MATCH: Checksum matches expected hash exactly.';
        } else {
            verifyBadge.classList.add('status-mismatch');
            targetHashInput.classList.add('status-mismatch');
            verifyBadge.firstElementChild.textContent = '❌';
            verifyText.textContent = 'MISMATCH: Checksum does NOT match expected hash.';
        }
    };

    /* ----------------------------------------------------
       3. EXECUTION PIPELINE
       ---------------------------------------------------- */
    const executeHash = async () => {
        if (isProcessing) return;

        const algorithm = getSelectedAlgorithm();
        execAlgoSpan.textContent = algorithm;

        if (currentMode === 'text') {
            const text = textInput.value;
            const encoding = encodingSelect.value;

            try {
                isProcessing = true;
                btnProcess.disabled = true;
                btnProcess.textContent = 'Hashing...';

                const { bytes, elapsedMs } = await engine.hashText(text, algorithm, encoding);
                currentDigestBytes = bytes;

                toolOutput.value = formatDigestOutput(bytes);
                execTimeSpan.textContent = `${elapsedMs.toFixed(2)} ms`;

                // Adjust textarea height
                toolOutput.style.height = 'auto';
                toolOutput.style.height = `${toolOutput.scrollHeight}px`;

                updateVerificationStatus();
            } catch (err) {
                toolOutput.value = `Error: ${err.message}`;
                execTimeSpan.textContent = 'Failed';
                updateVerificationStatus();
            } finally {
                isProcessing = false;
                btnProcess.disabled = false;
                btnProcess.textContent = 'Generate Checksum';
            }
        } else {
            // File Mode
            if (!selectedFile) {
                alert('Please select or drop a file to calculate checksum.');
                return;
            }

            const chunkSize = parseInt(chunkSizeSelect.value, 10) || 8388608;

            try {
                isProcessing = true;
                btnProcess.disabled = true;
                btnProcess.textContent = 'Streaming...';
                progressContainer.classList.add('active');
                progressBar.value = 0;
                progressPercent.textContent = '0%';
                progressSpeed.textContent = '0 MB/s';
                progressStatus.textContent = `Streaming ${selectedFile.name}...`;

                const { bytes, elapsedMs } = await engine.hashFileStream(
                    selectedFile,
                    algorithm,
                    chunkSize,
                    ({ percent, speedMBs }) => {
                        progressBar.value = percent;
                        progressPercent.textContent = `${Math.floor(percent)}%`;
                        progressSpeed.textContent = `${(speedMBs || 0).toFixed(1)} MB/s`;
                    }
                );

                currentDigestBytes = bytes;
                toolOutput.value = formatDigestOutput(bytes);
                execTimeSpan.textContent = `${(elapsedMs / 1000).toFixed(2)} s`;
                progressStatus.textContent = 'Hashing complete!';
                progressBar.value = 100;
                progressPercent.textContent = '100%';

                // Adjust output height
                toolOutput.style.height = 'auto';
                toolOutput.style.height = `${toolOutput.scrollHeight}px`;

                updateVerificationStatus();
            } catch (err) {
                if (err.name === 'AbortError') {
                    progressStatus.textContent = 'Hashing cancelled.';
                } else {
                    toolOutput.value = `Error: ${err.message}`;
                    progressStatus.textContent = 'Operation failed.';
                }
            } finally {
                isProcessing = false;
                btnProcess.disabled = false;
                btnProcess.textContent = 'Generate Checksum';
            }
        }
    };

    /* ----------------------------------------------------
       4. MODE TOGGLE HANDLERS
       ---------------------------------------------------- */
    const setMode = (mode) => {
        currentMode = mode;
        if (mode === 'text') {
            tabText.classList.add('active');
            tabText.setAttribute('aria-selected', 'true');
            tabFile.classList.remove('active');
            tabFile.setAttribute('aria-selected', 'false');

            containerText.classList.remove('hidden');
            containerFile.classList.add('hidden');
            settingTextEncoding.classList.remove('hidden');
            settingChunkSize.classList.add('hidden');

            if (autoProcessToggle.checked && textInput.value) {
                executeHash();
            }
        } else {
            tabFile.classList.add('active');
            tabFile.setAttribute('aria-selected', 'true');
            tabText.classList.remove('active');
            tabText.setAttribute('aria-selected', 'false');

            containerFile.classList.remove('hidden');
            containerText.classList.add('hidden');
            settingTextEncoding.classList.add('hidden');
            settingChunkSize.classList.remove('hidden');
        }
    };

    tabText.addEventListener('click', () => setMode('text'));
    tabFile.addEventListener('click', () => setMode('file'));

    /* ----------------------------------------------------
       5. TEXT INPUT HANDLERS
       ---------------------------------------------------- */
    const updateTextCounter = () => {
        const val = textInput.value;
        const charCount = val.length;
        const byteCount = new Blob([val]).size;
        textCounter.textContent = `${charCount} chars | ${formatBytes(byteCount)}`;
    };

    textInput.addEventListener('input', () => {
        updateTextCounter();
        if (autoProcessToggle.checked) {
            executeHash();
        }
    });

    /* ----------------------------------------------------
       6. FILE DRAG & DROP AND SELECTION HANDLERS
       ---------------------------------------------------- */
    const handleFileSelected = (file) => {
        if (!file) return;
        selectedFile = file;

        fileNameSpan.textContent = file.name;
        fileMetaSpan.textContent = `${formatBytes(file.size)} • ${file.type || 'Unknown MIME type'}`;
        fileInfoCard.classList.add('active');
        dropZone.classList.add('hidden');

        // Reset progress bar
        progressContainer.classList.remove('active');
        progressBar.value = 0;
        progressPercent.textContent = '0%';

        // If file is selected, trigger hash
        executeHash();
    };

    dropZone.addEventListener('click', () => filePicker.click());
    dropZone.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            filePicker.click();
        }
    });

    filePicker.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
            handleFileSelected(e.target.files[0]);
        }
    });

    // Drag & Drop
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleFileSelected(e.dataTransfer.files[0]);
        }
    });

    btnRemoveFile.addEventListener('click', () => {
        engine.cancelCurrentOperation();
        selectedFile = null;
        filePicker.value = '';
        fileInfoCard.classList.remove('active');
        dropZone.classList.remove('hidden');
        progressContainer.classList.remove('active');
    });

    btnCancelStream.addEventListener('click', () => {
        engine.cancelCurrentOperation();
    });

    /* ----------------------------------------------------
       7. VERIFICATION INPUT & BUTTON HANDLERS
       ---------------------------------------------------- */
    targetHashInput.addEventListener('input', () => {
        updateVerificationStatus();
    });

    btnProcess.addEventListener('click', () => {
        executeHash();
    });

    btnClear.addEventListener('click', () => {
        engine.cancelCurrentOperation();
        textInput.value = '';
        targetHashInput.value = '';
        toolOutput.value = '';
        selectedFile = null;
        filePicker.value = '';
        fileInfoCard.classList.remove('active');
        dropZone.classList.remove('hidden');
        progressContainer.classList.remove('active');
        updateTextCounter();
        updateVerificationStatus();
        execTimeSpan.textContent = '0.0 ms';
        engine.wipeMemory();
        currentDigestBytes = null;
    });

    btnCopy.addEventListener('click', async () => {
        const text = toolOutput.value;
        if (!text) return;

        try {
            await navigator.clipboard.writeText(text);
            const originalIcon = btnCopy.textContent;
            btnCopy.textContent = '✅';
            btnCopy.setAttribute('title', 'Copied to clipboard!');
            setTimeout(() => {
                btnCopy.textContent = originalIcon;
                btnCopy.setAttribute('title', 'Copy to clipboard');
            }, 1800);
        } catch (_) {
            toolOutput.select();
            document.execCommand('copy');
        }
    });

    btnWipe.addEventListener('click', () => {
        engine.wipeMemory();
        if (currentDigestBytes) {
            EncodingParser.wipe(currentDigestBytes);
            currentDigestBytes = null;
        }
        textInput.value = '';
        toolOutput.value = '';
        targetHashInput.value = '';
        updateTextCounter();
        updateVerificationStatus();
        execTimeSpan.textContent = 'Memory Cleared';
        alert('All sensitive input buffers and cryptographic digest bytes wiped with zeroes.');
    });

    /* ----------------------------------------------------
       8. SETTINGS & ALGORITHM CHANGE LISTENERS
       ---------------------------------------------------- */
    algoRadios.forEach(radio => {
        radio.addEventListener('change', () => {
            const algo = getSelectedAlgorithm();
            execAlgoSpan.textContent = algo;
            if (currentDigestBytes || (currentMode === 'text' && textInput.value) || (currentMode === 'file' && selectedFile)) {
                executeHash();
            }
        });
    });

    formatSelect.addEventListener('change', () => {
        if (currentDigestBytes) {
            toolOutput.value = formatDigestOutput(currentDigestBytes);
            updateVerificationStatus();
        }
    });

    encodingSelect.addEventListener('change', () => {
        if (currentMode === 'text' && textInput.value) {
            executeHash();
        }
    });

    // Initial counter setup & UI state
    updateTextCounter();
    updateVerificationStatus();
    execAlgoSpan.textContent = getSelectedAlgorithm();
});
