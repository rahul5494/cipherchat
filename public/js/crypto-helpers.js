// public/js/crypto-helpers.js
// This file contains all the client-side logic for handling end-to-end encryption.
// It uses the browser's built-in Web Crypto API for both asymmetric (RSA) and symmetric (AES) encryption.

const cryptoHelpers = {
    // --- ASYMMETRIC KEY (RSA-OAEP) HELPERS ---

    /**
     * Generates a new RSA-OAEP cryptographic key pair for encryption.
     * @returns {Promise<CryptoKeyPair>} A promise that resolves to a key pair object.
     */
    generateKeyPair: async function() {
        try {
            const keyPair = await window.crypto.subtle.generateKey({
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]), // 65537
                hash: "SHA-256",
            }, true, ["encrypt", "decrypt"]);
            return keyPair;
        } catch (error) {
            throw new Error('Could not generate cryptographic keys.');
        }
    },

    /**
     * Exports a CryptoKey object to a string format (Base64-encoded JWK).
     * @param {CryptoKey} key - The key to export (public or private).
     * @returns {Promise<string>} A promise that resolves to the key as a string.
     */
    exportKey: async function(key) {
        try {
            const exported = await window.crypto.subtle.exportKey("jwk", key);
            return JSON.stringify(exported);
        } catch (error) {
            throw new Error('Could not export key.');
        }
    },

    /**
     * Imports a public key from its string representation into a CryptoKey object.
     * @param {string} keyStr - The public key as a string (JWK format).
     * @returns {Promise<CryptoKey>} A promise that resolves to a public CryptoKey object.
     */
    importPublicKey: async function(keyStr) {
        try {
            const keyJwk = JSON.parse(keyStr);
            const key = await window.crypto.subtle.importKey("jwk", keyJwk, {
                name: "RSA-OAEP",
                hash: "SHA-256",
            }, true, ["encrypt"]);
            return key;
        } catch (error) {
            throw new Error('Could not import public key.');
        }
    },

    /**
     * Imports a private key from its string representation into a CryptoKey object.
     * @param {string} keyStr - The private key as a string (JWK format).
     * @returns {Promise<CryptoKey>} A promise that resolves to a private CryptoKey object.
     */
    importPrivateKey: async function(keyStr) {
        try {
            const keyJwk = JSON.parse(keyStr);
            const key = await window.crypto.subtle.importKey("jwk", keyJwk, {
                name: "RSA-OAEP",
                hash: "SHA-256",
            }, true, ["decrypt"]);
            return key;
        } catch (error) {
            throw new Error('Could not import private key.');
        }
    },

    /**
     * Encrypts a text message using a public key.
     * @param {string} message - The plaintext message to encrypt.
     * @param {CryptoKey} publicKey - The public key to use for encryption.
     * @returns {Promise<string>} A promise that resolves to the Base64-encoded encrypted message.
     */
    encryptMessage: async function(message, publicKey) {
        try {
            const encodedMessage = new TextEncoder().encode(message);
            const encryptedBuffer = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, encodedMessage);
            return window.btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedBuffer)));
        } catch (error) {
            return null;
        }
    },

    /**
     * Decrypts a message using a private key.
     * @param {string} encryptedBase64 - The Base64-encoded encrypted message.
     * @param {CryptoKey} privateKey - The private key to use for decryption.
     * @returns {Promise<string|null>} A promise that resolves to the decrypted plaintext message, or null if decryption fails.
     */
    decryptMessage: async function(encryptedBase64, privateKey) {
        try {
            const encryptedBuffer = Uint8Array.from(window.atob(encryptedBase64), c => c.charCodeAt(0));
            const decryptedBuffer = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedBuffer);
            return new TextDecoder().decode(decryptedBuffer);
        } catch (error) {
            return null;
        }
    },

    // --- SYMMETRIC KEY (AES-GCM) HELPERS FOR FILE ENCRYPTION ---

    /**
     * Generates a new symmetric AES-GCM key for file encryption.
     * @returns {Promise<CryptoKey>} A promise that resolves to a symmetric key.
     */
    generateFileKey: async function() {
        return await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    },

    /**
     * Encrypts a file buffer using a symmetric key.
     * @param {ArrayBuffer} fileBuffer - The raw data of the file.
     * @param {CryptoKey} fileKey - The symmetric key to use for encryption.
     * @returns {Promise<{iv: Uint8Array, encryptedFile: ArrayBuffer}>} An object containing the initialization vector and the encrypted file data.
     */
    encryptFile: async function(fileBuffer, fileKey) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Generate a random IV
        const encryptedFile = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, fileBuffer);
        return { iv, encryptedFile };
    },

    /**
     * Decrypts a file buffer using a symmetric key.
     * @param {ArrayBuffer} encryptedData - The encrypted file data, with the IV prepended.
     * @param {CryptoKey} fileKey - The symmetric key to use for decryption.
     * @returns {Promise<ArrayBuffer>} A promise that resolves to the decrypted file data.
     */
    decryptFile: async function(encryptedData, fileKey) {
        const iv = encryptedData.slice(0, 12); // Extract the IV from the start of the data
        const file = encryptedData.slice(12); // The rest is the actual encrypted file
        return await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, fileKey, file);
    },

    // --- KEY STORAGE IN BROWSER ---

    saveKeyPair: async function(keyPair) {
        try {
            const publicKeyStr = await this.exportKey(keyPair.publicKey);
            const privateKeyStr = await this.exportKey(keyPair.privateKey);
            localStorage.setItem('cipherChatPublicKey', publicKeyStr);
            localStorage.setItem('cipherChatPrivateKey', privateKeyStr);
        } catch (error) {
        }
    },

    loadKeyPair: async function() {
        const publicKeyStr = localStorage.getItem('cipherChatPublicKey');
        const privateKeyStr = localStorage.getItem('cipherChatPrivateKey');

        if (!publicKeyStr || !privateKeyStr) {
            return null;
        }

        try {
            const publicKey = await this.importPublicKey(publicKeyStr);
            const privateKey = await this.importPrivateKey(privateKeyStr);
            return { publicKey, privateKey };
        } catch (error) {
            this.deleteKeyPair();
            return null;
        }
    },

    deleteKeyPair: function() {
        localStorage.removeItem('cipherChatPublicKey');
        localStorage.removeItem('cipherChatPrivateKey');
    }
};
