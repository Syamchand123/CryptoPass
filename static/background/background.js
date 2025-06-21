

// static/background/background.js

// --- Use importScripts ---
try {
    importScripts('./argon2-browser.js'); // Path relative to background.js in the DIST folder
    if (typeof argon2 === 'undefined') {
        console.error("argon2-browser.js was loaded via importScripts, but the global 'argon2' object is not defined.");
        throw new Error("Global 'argon2' object not found. Check argon2-browser.js bundling or UMD wrapper.");
    }
   //console.log("argon2-browser.js loaded successfully. Global 'argon2' object is available.");
} catch (e) {
    console.error("Failed to load or initialize argon2-browser.js via importScripts:", e);
}

//console.log("CryptoPass Background Service Worker Started.");

// --- Global State Variables ---
let masterKeyBinary = null;
let masterKeyDerivedFromPassphrase = "";
let storageEncryptionKey = null; // Cached CryptoKey for AES-GCM

const ENCRYPTION_KEY_INFO_STRING = "CryptoPassStorageEncryptionKey_v1";
const STORAGE_KEY_MAPPINGS = "cryptoPassMappings_encrypted_v1";
const UNENCRYPTED_WEBAUTHN_IDS_KEY = "cryptoPassWebAuthnIDs_v1";
// Argon2id configuration
const argon2Config = {
    pass: '', // Will be set per call
    salt: 'CryptoPassSalt',
    time: 3,
    mem: 65536, // 64MB
    hashLen: 32, // 32 bytes (256 bits)
    parallelism: 1,
    type: typeof argon2 !== 'undefined' ? argon2.ArgonType.Argon2id : undefined,
};

// Inactivity timer
let inactivityTimer = null;
const INACTIVITY_TIMEOUT = 5 * 60 * 1000; // 5 minutes


// --- Core Cryptographic and State Management Functions ---

/**
 * Derives a Master Key (binary) from a master passphrase using Argon2id (WASM).
 * Caches the result in memory for the session.
 * Crucially, clears any cached storageEncryptionKey if the masterKeyBinary is re-derived.
 */
async function deriveAndCacheMasterKey(masterPassphrase) {
    //console.log("[DERIVEMASTERKEY] Attempting derivation/cache for passphrase (length):", masterPassphrase ? masterPassphrase.length : "Undefined");

    if (masterKeyBinary && masterKeyDerivedFromPassphrase === masterPassphrase) {
        //console.log("[DERIVEMASTERKEY] Using cached masterKeyBinary. Master Passphrase matches cached source.");
        //console.log("[DERIVEMASTERKEY] Cached masterKeyBinary (first 4 bytes hex):",masterKeyBinary ? Array.from(masterKeyBinary.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('') : "NULL");
        return masterKeyBinary;
    }

    //console.log("[DERIVEMASTERKEY] Master Passphrase differs or no cached masterKeyBinary. Proceeding to derive new masterKeyBinary.");

    if (typeof argon2 === 'undefined' || typeof argon2.hash !== 'function' || typeof argon2.ArgonType === 'undefined') {
        const errorMessage = "Argon2 library is not properly loaded or initialized. Cannot derive master key.";
        console.error(errorMessage);
        throw new Error(errorMessage);
    }
    if (argon2Config.type === undefined) {
        const errorMessage = "argon2.ArgonType.Argon2id not defined. Argon2 library might not have loaded correctly.";
        console.error(errorMessage);
        throw new Error(errorMessage);
    }

    try {
        const result = await argon2.hash({
            ...argon2Config,
            pass: masterPassphrase,
        });

        masterKeyBinary = result.hash;
        masterKeyDerivedFromPassphrase = masterPassphrase;

        //("[DERIVEMASTERKEY] NEW masterKeyBinary derived (first 4 bytes hex):",masterKeyBinary ? Array.from(masterKeyBinary.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('') : "NULL");

        if (storageEncryptionKey) {
            // //("[DERIVEMASTERKEY] Clearing previously cached storageEncryptionKey because masterKeyBinary was (re)derived.");
            storageEncryptionKey = null;
        } else {
            // //("[DERIVEMASTERKEY] No previously cached storageEncryptionKey to clear (it was already null or this is init).");
        }

        // //("[DERIVEMASTERKEY] Master key derived and cached. Source passphrase updated.");
        return masterKeyBinary;

    } catch (err) {
        console.error("[DERIVEMASTERKEY] Error deriving master key with Argon2:", err);
        masterKeyBinary = null;
        masterKeyDerivedFromPassphrase = "";
        storageEncryptionKey = null;
        throw err;
    }
}

/**
 * Derives and caches an AES-GCM encryption key from the Master_Key_Binary.
 */
async function getStorageEncryptionKey(currentActualMasterKeyBinary) {
    const currentMasterKeyHex = currentActualMasterKeyBinary ? Array.from(currentActualMasterKeyBinary.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('') : "NULL";
    const globalMasterKeyHex = masterKeyBinary ? Array.from(masterKeyBinary.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('') : "NULL";

    // //(`[GETSTORAGEENCKEY] Called. Param currentActualMasterKeyBinary (hex): ${currentMasterKeyHex}. Global masterKeyBinary (hex): ${globalMasterKeyHex}.`);

    if (storageEncryptionKey && masterKeyBinary && currentActualMasterKeyBinary &&
        masterKeyBinary.length === currentActualMasterKeyBinary.length &&
        masterKeyBinary.every((val, index) => val === currentActualMasterKeyBinary[index])) {
        //  //("[GETSTORAGEENCKEY] Global masterKeyBinary exists and currentActualMasterKeyBinary matches it. Checking for cached storageEncryptionKey.");
         if (storageEncryptionKey) { // This condition is somewhat redundant due to the outer if, but safe.
            // //("[GETSTORAGEENCKEY] Using CACHED storageEncryptionKey. It was derived from the current global masterKeyBinary.");
            return storageEncryptionKey;
         } else {
            // //("[GETSTORAGEENCKEY] storageEncryptionKey is NULL, though masterKeyBinary seems current. Will derive new storage key.");
         }
    } else if (storageEncryptionKey) {
        console.warn("[GETSTORAGEENCKEY] Cached storageEncryptionKey exists, but global masterKeyBinary has changed or param currentActualMasterKeyBinary doesn't match. Forcing re-derivation.");
    }

    if (!currentActualMasterKeyBinary || currentActualMasterKeyBinary.length === 0) {
        console.error("[GETSTORAGEENCKEY] Cannot derive storage encryption key: currentActualMasterKeyBinary is invalid or empty.");
        throw new Error("Cannot derive storage encryption key without a valid Master Key Binary.");
    }

    // //("[GETSTORAGEENCKEY] Deriving NEW storageEncryptionKey from currentActualMasterKeyBinary (hex):", currentMasterKeyHex);
    try {
        const hmacKeyForDerivation = await crypto.subtle.importKey(
            "raw", currentActualMasterKeyBinary, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
        const encoder = new TextEncoder();
        const derivedBytes = await crypto.subtle.sign(
            "HMAC", hmacKeyForDerivation, encoder.encode(ENCRYPTION_KEY_INFO_STRING)
        );
        const newKey = await crypto.subtle.importKey(
            "raw", derivedBytes, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]
        );
        storageEncryptionKey = newKey;
        // //("[GETSTORAGEENCKEY] NEW storageEncryptionKey derived and cached.");
        return storageEncryptionKey;
    } catch (error) {
        console.error("[GETSTORAGEENCKEY] Error deriving storage encryption key:", error);
        storageEncryptionKey = null;
        throw error;
    }
}

function lockMasterKey() {
    masterKeyBinary = null;
    masterKeyDerivedFromPassphrase = "";
    storageEncryptionKey = null;
    // //("Master key and storage encryption key cleared from memory (locked).");
    chrome.runtime.sendMessage({ action: "updateLockState", locked: true }).catch(e => console.warn("Could not send lock state update", e));
}

function resetInactivityTimer() {
    if (masterKeyBinary) {
        clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(lockMasterKey, INACTIVITY_TIMEOUT);
    }
}

// --- Encryption/Decryption Helper Functions ---
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = atob(base64);
    const bytes = new Uint8Array(binary_string.length);
    for (let i = 0; i < binary_string.length; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

async function encryptData(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(JSON.stringify(data));

    // //("[ENCRYPT] IV (bytes):", iv);
    // //("[ENCRYPT] Data to encrypt (stringified):", JSON.stringify(data));

    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, encodedData
    );

    // //("[ENCRYPT] Base64 IV:", arrayBufferToBase64(iv.buffer));
    // //("[ENCRYPT] Base64 Ciphertext:", arrayBufferToBase64(ciphertextBuffer));

    return {
        iv: arrayBufferToBase64(iv.buffer),
        ciphertext: arrayBufferToBase64(ciphertextBuffer)
    };
}

async function decryptData(key, base64Iv, base64Ciphertext) {
    // //("[DECRYPT] Using Base64 IV:", base64Iv);
    // //("[DECRYPT] Using Base64 Ciphertext:", base64Ciphertext);
    try {
        const ivBuffer = base64ToArrayBuffer(base64Iv);
        const ciphertextBuffer = base64ToArrayBuffer(base64Ciphertext);
        const decoder = new TextDecoder();
        // //("[DECRYPT] IV (bytes from ArrayBuffer):", new Uint8Array(ivBuffer));

        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: new Uint8Array(ivBuffer) }, key, ciphertextBuffer
        );
        const decryptedString = decoder.decode(decryptedBuffer);
        // //("[DECRYPT] Decrypted String:", decryptedString);
        return JSON.parse(decryptedString);
    } catch (error) {
        console.error("[DECRYPT] Decryption failed raw error:", error); // Log the original error for detailed diagnostics
        console.error("[DECRYPT] Decryption failed (likely OperationError):", error.name, error.message);
        throw new Error("Failed to decrypt mappings. Master key may have changed or data is corrupt.");
    }
}

// --- Password Generation and Transformation ---
async function generatePasswordWithWebCrypto(derivedMasterKey, domain, username, otop, profileOptions) {
    if (!derivedMasterKey || derivedMasterKey.length === 0) {
        throw new Error("Derived master key is not available or empty.");
    }
    try {
        const dataToHash = `${domain.toLowerCase()}${username}${otop}`;
        const encoder = new TextEncoder();
        const cryptoKey = await crypto.subtle.importKey(
            "raw", derivedMasterKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
        const signatureBuffer = await crypto.subtle.sign(
            "HMAC", cryptoKey, encoder.encode(dataToHash)
        );
        return transformHmacToPassword(signatureBuffer, profileOptions);
    } catch (error) {
        console.error("Error in generatePasswordWithWebCrypto or transformation:", error);
        throw error;
    }
}

function transformHmacToPassword(hmacBuffer, profileOptions) {
    const bytes = new Uint8Array(hmacBuffer);
    const options = {
        length: 16,
        includeLowercase: true,
        includeUppercase: true,
        includeNumbers: true,
        includeSymbols: true,
        customSymbols: "!@#$%^&*-+=_?",
        requireEachCategory: true,
        ...profileOptions,
    };
    const charCategories = {
        lowercase: "abcdefghijklmnopqrstuvwxyz",
        uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        numbers: "0123456789",
        symbols: options.customSymbols || "!@#$%^&*-+=_?",
    };
    let availableChars = "";
    const requiredCategories = [];

    if (options.includeLowercase) { availableChars += charCategories.lowercase; if (options.requireEachCategory) requiredCategories.push('lowercase'); }
    if (options.includeUppercase) { availableChars += charCategories.uppercase; if (options.requireEachCategory) requiredCategories.push('uppercase'); }
    if (options.includeNumbers) { availableChars += charCategories.numbers; if (options.requireEachCategory) requiredCategories.push('numbers'); }
    if (options.includeSymbols) { availableChars += charCategories.symbols; if (options.requireEachCategory) requiredCategories.push('symbols'); }
    if (availableChars.length === 0) availableChars = charCategories.lowercase + charCategories.numbers;

    let password = "";
    let byteIdx = 0;
    let entropyIdx = 0;
    for (let i = 0; i < options.length; i++) {
        const pseudoRandomValue = (bytes[byteIdx] + entropyIdx) % 256;
        password += availableChars[pseudoRandomValue % availableChars.length];
        byteIdx = (byteIdx + 1) % bytes.length;
        entropyIdx = (entropyIdx + bytes[(byteIdx + i) % bytes.length] + 1) % 25600;
    }
    if (options.requireEachCategory && requiredCategories.length > 0) {
        let passArray = password.split('');
        const currentCategoriesPresent = new Set();
        if (options.includeLowercase && /[a-z]/.test(password)) currentCategoriesPresent.add('lowercase');
        if (options.includeUppercase && /[A-Z]/.test(password)) currentCategoriesPresent.add('uppercase');
        if (options.includeNumbers && /[0-9]/.test(password)) currentCategoriesPresent.add('numbers');
        if (options.includeSymbols && new RegExp(`[${escapeRegExp(charCategories.symbols)}]`).test(password)) currentCategoriesPresent.add('symbols');
        let replacementAttempt = 0;
        for (const category of requiredCategories) {
            if (!currentCategoriesPresent.has(category)) {
                const posToReplace = (bytes[(byteIdx + replacementAttempt) % bytes.length] + entropyIdx) % options.length;
                const charSetForCategory = charCategories[category];
                const charToInsert = charSetForCategory[(bytes[(byteIdx + replacementAttempt + 1) % bytes.length] + entropyIdx) % charSetForCategory.length];
                passArray[posToReplace] = charToInsert;
                byteIdx = (byteIdx + 1) % bytes.length;
                entropyIdx = (entropyIdx + bytes[(byteIdx + replacementAttempt) % bytes.length] + 1) % 25600;
                replacementAttempt++;
            }
        }
        password = passArray.join('');
    }
    return password;
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// --- Storage Interaction Functions (using encryption) ---
async function getMappings() {
    if (!masterKeyBinary) {
        console.warn("[GETMAPPINGS] Attempted to get mappings while masterKeyBinary is null (locked). Returning empty object.");
        return {}; // Return empty object, not null or undefined, to prevent downstream errors.
    }
    try {
        const encKey = await getStorageEncryptionKey(masterKeyBinary);
        // //("[GETMAPPINGS] Using encryption key object for get:", encKey ? "Exists" : "NULL");
        const result = await chrome.storage.local.get([STORAGE_KEY_MAPPINGS]);
        const storedEncryptedData = result[STORAGE_KEY_MAPPINGS];
        if (!storedEncryptedData || !storedEncryptedData.iv || !storedEncryptedData.ciphertext) {
            // //("[GETMAPPINGS] No encrypted mappings found or data is malformed. Returning empty object.");
            return {};
        }
        // //("[GETMAPPINGS] Found stored encrypted data:", storedEncryptedData);
        return await decryptData(encKey, storedEncryptedData.iv, storedEncryptedData.ciphertext);
    } catch (error) {
        console.error("[GETMAPPINGS] Error getting and decrypting mappings:", error.name, error.message, error.stack);
        return {}; // Return empty on error to allow app to continue, though with missing data.
    }
}

async function saveMappings(mappingsData) {
    if (!masterKeyBinary) {
        console.error("[SAVEMAPPINGS] Cannot save mappings: Extension is locked (masterKeyBinary is null).");
        throw new Error("Cannot save mappings. Extension is locked.");
    }
    try {
        const encKey = await getStorageEncryptionKey(masterKeyBinary);
        // //("[SAVEMAPPINGS] Using encryption key object for save:", encKey ? "Exists" : "NULL");
        // //("[SAVEMAPPINGS] Data to save (before encrypt):", mappingsData);
        const encryptedPayload = await encryptData(encKey, mappingsData);
        // //("[SAVEMAPPINGS] Payload to store:", encryptedPayload);
        await chrome.storage.local.set({ [STORAGE_KEY_MAPPINGS]: encryptedPayload });
        return { success: true };
    } catch (error) {
        console.error("[SAVEMAPPINGS] Error encrypting and saving mappings:", error.name, error.message);
        return { success: false, error: error.message };
    }
}

async function addMapping(domain, username) {
    if (!domain || !username) return { success: false, error: "Domain and username required." };
    domain = domain.toLowerCase();
    try {
        const mappings = await getMappings();
        if (Object.keys(mappings).length === 0 && !masterKeyBinary) { /* Check if getMappings returned empty due to being locked vs actual empty*/ }

        if (!mappings[domain]) mappings[domain] = [];
        if (!mappings[domain].includes(username)) {
            mappings[domain].push(username);
            mappings[domain].sort();
            return await saveMappings(mappings);
        }
        return { success: false, error: "Username already exists for this domain." };
    } catch (error) {
        console.error("Error in addMapping process:", error.name, error.message);
        return { success: false, error: error.message };
    }
}

async function removeMapping(domain, username) {
    if (!domain || !username) return { success: false, error: "Domain and username required." };
    domain = domain.toLowerCase();
    try {
        const mappings = await getMappings();
        if (mappings[domain] && mappings[domain].includes(username)) {
            mappings[domain] = mappings[domain].filter(u => u !== username);
            if (mappings[domain].length === 0) delete mappings[domain];
            return await saveMappings(mappings);
        }
        return { success: false, error: "Mapping not found." };
    } catch (error) {
        console.error("Error in removeMapping process:", error.name, error.message);
        return { success: false, error: error.message };
    }
}

async function getUsernamesForDomain(domain) {
    if (!domain) return { usernames: [] };
    domain = domain.toLowerCase();
    try {
        const mappings = await getMappings(); // This will be decrypted
        return { usernames: mappings[domain] || [] };
    } catch (error) { // This catch might not be strictly necessary if getMappings handles its errors by returning {}
        console.error("Error in getUsernamesForDomain (potentially from getMappings):", error.name, error.message);
        return { usernames: [], error: error.message };
    }
}




































const WEBAUTHN_CREDENTIALS_KEY = "cryptoPassWebAuthnCredentials_encrypted_v1"; // Will store an array of {id, pubKeyAlg}
const SETTINGS_KEY = "cryptoPassSettings_encrypted_v1"; // For storing { useWebAuthnUnlock: true }
let currentWebAuthnChallengeForAuth = null; // To store challenge for get()

// Helper for WebAuthn: ArrayBuffer to Base64URL (different from standard Base64)
/*function bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
    }
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}*/
/*function bufferToBase64URL(buffer) { // This is one of the suspects
    if (!buffer || buffer.byteLength === 0) { // ADDED CHECK for empty/null buffer
        console.error("[BG_B64URL] bufferToBase64URL received null or empty buffer!");
        return ""; // Return empty string if buffer is bad
    }
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
    }
    const b64 = btoa(str);
    return b64            // Standard Base64
        .replace(/\+/g, '-') // Base64URL specific
        .replace(/\//g, '_') // Base64URL specific
        .replace(/=/g, '');  // Base64URL specific (remove padding)
}
const objectToUint8Array_BG = (obj, fieldName = "UnknownField") => {
    if (!obj) { console.warn(`BG [ObjToArr]: Field '${fieldName}' is null/undefined.`); return new Uint8Array(0); }
    if (obj instanceof Uint8Array) return obj;
    if (obj instanceof ArrayBuffer) return new Uint8Array(obj);
    if (Array.isArray(obj) && obj.every(item => typeof item === 'number')) { return Uint8Array.from(obj); }
    if (typeof obj === 'object' && obj !== null && typeof obj.length === 'number') {
        const arr = new Uint8Array(obj.length); for (let i = 0; i < obj.length; i++) arr[i] = obj[i] || 0; return arr;
    }
    if (typeof obj === 'object' && obj !== null) {
        const keys = Object.keys(obj).map(Number).filter(k=>!isNaN(k)&&k>=0).sort((a,b)=>a-b);
        if (keys.length > 0 && keys.every((k,i)=>k===i)) {
            const arr = new Uint8Array(keys.length); for (let i = 0; i < keys.length; i++) arr[i] = obj[i] || 0; return arr;
        }
    }
    console.error(`BG [ObjToArr]: Failed to convert field '${fieldName}'.`); return new Uint8Array(0);
};*/

/*function bufferToBase64URL(buffer) {
    // Convert ArrayBuffer to Uint8Array if needed
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}*/

// Helper: Base64URL to ArrayBuffer
/*function base64URLToBuffer(base64url) {
    base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64url.length % 4)) % 4;
    base64url += '='.repeat(padLength);
    const raw = atob(base64url);
    const buffer = new ArrayBuffer(raw.length);
    const Nbyte = new Uint8Array(buffer);
    for (let i = 0; i < raw.length; i++) {
        Nbyte[i] = raw.charCodeAt(i);
    }
    return buffer;
}*/
function base64URLToBuffer(base64url) {
    base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64url.length % 4)) % 4;
    base64url += '='.repeat(padLength);
    const raw = atob(base64url);
    const buffer = new ArrayBuffer(raw.length);
    const Nbyte = new Uint8Array(buffer);
    for (let i = 0; i < raw.length; i++) {
        Nbyte[i] = raw.charCodeAt(i);
    }
    return Nbyte; // <--- Return Uint8Array, not buffer!
}


async function getWebAuthnCredentials() {
    // This function will use the same encryption as `getMappings`
    if (!masterKeyBinary) {
        console.warn("[WEBAUTHN] Cannot get credentials, masterKeyBinary is null (locked).");
        return []; // Return empty array if locked or no credentials
    }
    try {
        const encKey = await getStorageEncryptionKey(masterKeyBinary);
        const result = await chrome.storage.local.get([WEBAUTHN_CREDENTIALS_KEY]);
        const storedEncryptedData = result[WEBAUTHN_CREDENTIALS_KEY];

        if (!storedEncryptedData || !storedEncryptedData.iv || !storedEncryptedData.ciphertext) {
            return []; // No credentials stored or malformed
        }
        const credentials = await decryptData(encKey, storedEncryptedData.iv, storedEncryptedData.ciphertext);
        return Array.isArray(credentials) ? credentials : []; // Ensure it's an array
    } catch (error) {
        console.error("[WEBAUTHN] Error getting/decrypting WebAuthn credentials:", error);
        return []; // On error, return empty, signaling potential corruption or key mismatch
    }
}

async function saveWebAuthnCredentials(credentialsArray) {
    // This function will use the same encryption as `saveMappings`
    if (!masterKeyBinary) {
        throw new Error("[WEBAUTHN] Cannot save credentials: Extension is locked.");
    }
    try {
        const encKey = await getStorageEncryptionKey(masterKeyBinary);
        const encryptedPayload = await encryptData(encKey, credentialsArray); // credentialsArray is the JS object to encrypt
        await chrome.storage.local.set({ [WEBAUTHN_CREDENTIALS_KEY]: encryptedPayload });
        return { success: true };
    } catch (error) {
        console.error("[WEBAUTHN] Error encrypting/saving WebAuthn credentials:", error);
        return { success: false, error: error.message };
    }
}

async function getSettings() {
    if (!masterKeyBinary) return { useWebAuthnUnlock: false }; // Default if locked
    try {
        const encKey = await getStorageEncryptionKey(masterKeyBinary);
        const result = await chrome.storage.local.get([SETTINGS_KEY]);
        const storedEncryptedData = result[SETTINGS_KEY];
        if (!storedEncryptedData || !storedEncryptedData.iv || !storedEncryptedData.ciphertext) {
            return { useWebAuthnUnlock: false }; // Default if no settings
        }
        const settings = await decryptData(encKey, storedEncryptedData.iv, storedEncryptedData.ciphertext);
        return settings || { useWebAuthnUnlock: false };
    } catch (error) {
        console.error("[SETTINGS] Error getting/decrypting settings:", error);
        return { useWebAuthnUnlock: false }; // Default on error
    }
}

async function saveSettings(settingsObject) {
    if (!masterKeyBinary) throw new Error("[SETTINGS] Cannot save settings: Extension is locked.");
    try {
        const encKey = await getStorageEncryptionKey(masterKeyBinary);
        const encryptedPayload = await encryptData(encKey, settingsObject);
        await chrome.storage.local.set({ [SETTINGS_KEY]: encryptedPayload });
        return { success: true };
    } catch (error) {
        console.error("[SETTINGS] Error encrypting/saving settings:", error);
        return { success: false, error: error.message };
    }
}






const UNENCRYPTED_PREFERENCES_KEY = "cryptoPassPreferences_v1";
async function getUnlockPreferences() {
    try {
        const r = await chrome.storage.local.get([UNENCRYPTED_PREFERENCES_KEY]);
        return r[UNENCRYPTED_PREFERENCES_KEY] || { useWebAuthnUnlock: false, hasRegisteredWebAuthnKeys: false };
    } catch (e) { console.error("BG: Error getting unencrypted prefs", e); return { useWebAuthnUnlock: false, hasRegisteredWebAuthnKeys: false }; }
}
async function saveUnlockPreferences(prefs) {
    try { await chrome.storage.local.set({ [UNENCRYPTED_PREFERENCES_KEY]: prefs }); return { success: true }; }
    catch (e) { console.error("BG: Error saving unencrypted prefs", e); return { success: false, error: e.message }; }
}







async function getWebAuthnCredentialsUnencrypted() {
    try {
        const r = await chrome.storage.local.get([WEBAUTHN_CREDENTIALS_STORAGE_KEY + "_unencrypted_ids"]); // New key
        const data = r[WEBAUTHN_CREDENTIALS_STORAGE_KEY + "_unencrypted_ids"];
        return Array.isArray(data) ? data : [];
    } catch (e) {
        console.error("[BG_GETWACREDS_UNENC] Error getting unencrypted cred IDs:", e);
        return [];
    }
}
async function saveWebAuthnCredentialsUnencrypted(credsArray) { // credsArray is just [{id: "base64url"}, ...]
    try {
        await chrome.storage.local.set({ [WEBAUTHN_CREDENTIALS_STORAGE_KEY + "_unencrypted_ids"]: credsArray });
        return { success: true };
    } catch (e) {
        console.error("[BG_SAVEWACREDS_UNENC] Error saving unencrypted cred IDs:", e);
        return { success: false, error: e.message };
    }
}




async function getWebAuthnCredentialIDs() { // Renamed and simplified
    try {
        const r = await chrome.storage.local.get([UNENCRYPTED_WEBAUTHN_IDS_KEY]);
        const data = r[UNENCRYPTED_WEBAUTHN_IDS_KEY];
        // //("[BG_GETWA_IDS] Fetched unencrypted cred IDs:", data);
        return Array.isArray(data) ? data : []; // Should be an array of {id: "base64url"}
    } catch (e) {
        console.error("[BG_GETWA_IDS] Error getting unencrypted cred IDs:", e);
        return [];
    }
}
async function saveWebAuthnCredentialIDs(credsIdArray) { // Renamed
    try {
        await chrome.storage.local.set({ [UNENCRYPTED_WEBAUTHN_IDS_KEY]: credsIdArray });
        // //("[BG_SAVEWA_IDS] Saved unencrypted cred IDs:", credsIdArray);
        return { success: true };
    } catch (e) {
        console.error("[BG_SAVEWA_IDS] Error saving unencrypted cred IDs:", e);
        return { success: false, error: e.message };
    }
}


/*const objectToUint8Array_BG = (obj, fieldName = "UnknownField_BG") => {
    if (!obj) { console.warn(`BG [ObjToArr]: Field '${fieldName}' is null/undefined.`); return new Uint8Array(0); }
    if (obj instanceof Uint8Array) { return obj; }
    if (obj instanceof ArrayBuffer) { return new Uint8Array(obj); }
    if (Array.isArray(obj) && obj.every(item => typeof item === 'number')) {
        return Uint8Array.from(obj);
    }
    if (typeof obj === 'object' && obj !== null && typeof obj.length === 'number') {
        const arr = new Uint8Array(obj.length); for (let i = 0; i < obj.length; i++) arr[i] = obj[i] || 0;
        return arr;
    }
    if (typeof obj === 'object' && obj !== null) {
        const numericKeys = Object.keys(obj).map(Number).filter(k=>!isNaN(k)&&k>=0).sort((a,b)=>a-b);
        if (numericKeys.length > 0 && numericKeys.every((k,i)=>k===i)) {
            const arr = new Uint8Array(numericKeys.length); for (let i = 0; i < numericKeys.length; i++) arr[i] = obj[i] || 0;
            return arr;
        }
    }
    console.error(`BG [ObjToArr]: Failed to convert field '${fieldName}'. Type: ${typeof obj}, Val (snip):`, JSON.stringify(obj).slice(0,100));
    return new Uint8Array(0);
};*/

const objectToUint8Array_BG = (obj, fieldName = "UnknownField_BG") => {
  if (!obj) {
    console.warn(`BG [ObjToArr]: Field '${fieldName}' is null/undefined.`);
    return new Uint8Array(0);
  }

  // Already a Uint8Array
  if (obj instanceof Uint8Array) {
    return obj;
  }

  // ArrayBuffer
  if (obj instanceof ArrayBuffer) {
    return new Uint8Array(obj);
  }

  // Regular array of numbers
  if (Array.isArray(obj)) {
    if (obj.every(item => typeof item === 'number' && Number.isInteger(item))) {
      return Uint8Array.from(obj.map(val => Math.max(0, Math.min(255, val))));
    } else {
      console.error(`BG [ObjToArr]: Array contains non-numeric values in field '${fieldName}'`);
      return new Uint8Array(0);
    }
  }

  // Array-like object with length property (like arguments, NodeList, etc.)
  if (typeof obj === 'object' && obj !== null && typeof obj.length === 'number' && obj.length >= 0) {
    const arr = new Uint8Array(obj.length);
    for (let i = 0; i < obj.length; i++) {
      const val = obj[i];
      if (typeof val === 'number' && Number.isInteger(val)) {
        arr[i] = Math.max(0, Math.min(255, val));
      } else {
        arr[i] = 0;
      }
    }
    return arr;
  }

  // Object with numeric keys (more flexible approach)
  if (typeof obj === 'object' && obj !== null) {
    const numericEntries = Object.entries(obj)
      .filter(([key, val]) => !isNaN(Number(key)) && Number(key) >= 0 && typeof val === 'number')
      .map(([key, val]) => [Number(key), val])
      .sort(([a], [b]) => a - b);

    if (numericEntries.length > 0) {
      // Find the maximum index to determine array length  
      const maxIndex = numericEntries[numericEntries.length - 1][0];
      const arr = new Uint8Array(maxIndex + 1);
      
      // Fill the array with values, defaulting to 0 for missing indices
      numericEntries.forEach(([index, value]) => {
        arr[index] = Math.max(0, Math.min(255, value));
      });
      
      return arr;
    }
  }

  console.error(`BG [ObjToArr]: Failed to convert field '${fieldName}'. Type: ${typeof obj}, Val (snip):`, 
    JSON.stringify(obj).slice(0, 100));
  return new Uint8Array(0);
};

function bufferToBase64URL(bufferOrView) {
    if (!bufferOrView) { console.error("[BG_B64URL] Null/undefined buffer/view."); return ""; }
    let buffer;
    if (bufferOrView instanceof Uint8Array) {
        buffer = bufferOrView.byteLength === bufferOrView.buffer.byteLength ? bufferOrView.buffer : bufferOrView.buffer.slice(bufferOrView.byteOffset, bufferOrView.byteOffset + bufferOrView.byteLength);
    } else if (bufferOrView instanceof ArrayBuffer) {
        buffer = bufferOrView;
    } else { console.error("[BG_B64URL] Invalid type. Expected ArrayBuffer or Uint8Array. Got:", typeof bufferOrView); return ""; }
    if (buffer.byteLength === 0) { console.warn("[BG_B64URL] Empty ArrayBuffer (byteLength 0)."); return ""; }
    const bytes = new Uint8Array(buffer); let str = '';
    for (const charCode of bytes) { str += String.fromCharCode(charCode); }
    const b64 = btoa(str); return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}






// --- Message Listener (Handles communication with Popup) ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // //("Message received in background:", request.action, request.data);
    resetInactivityTimer();

    if (request.action === "getDomain") {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (chrome.runtime.lastError) {
                console.error("Error querying tabs:", chrome.runtime.lastError.message);
                sendResponse({ domain: null, error: "Error querying tabs" }); return;
            }
            if (tabs && tabs.length > 0 && tabs[0].url) {
                try {
                    const url = new URL(tabs[0].url);
                    if (url.protocol === "http:" || url.protocol === "https:") {
                        sendResponse({ domain: url.hostname });
                    } else {
                        sendResponse({ domain: null, note: "Not a web page" });
                    }
                } catch (e) {
                    sendResponse({ domain: null, error: "Invalid URL" });
                }
            } else {
                sendResponse({ domain: null, error: "No active tab or URL found" });
            }
        });
        return true;
    }

    if (request.action === "generatePassword") {
        const { masterPassphrase, domain, username, otop, profileOptions } = request.data;
        if (!masterPassphrase || !domain || !otop) {
            sendResponse({ error: "Missing required fields for password generation." }); return false;
        }
        if (typeof argon2 === 'undefined' || typeof argon2.hash !== 'function') {
             sendResponse({ error: "Argon2 library not loaded." }); return false;
        }
        const effectiveProfileOptions = profileOptions || { /* Default profile options */
            length: 18, includeLowercase: true, includeUppercase: true, includeNumbers: true,
            includeSymbols: true, customSymbols: "!@#$%^&*-+=_?", requireEachCategory: true
        };
        deriveAndCacheMasterKey(masterPassphrase)
            .then(derivedKey => {
                if (!derivedKey) throw new Error("Master key derivation failed.");
                return generatePasswordWithWebCrypto(derivedKey, domain, username, otop, effectiveProfileOptions);
            })
            .then(password => {
                // //("Transformed Password generated:", password);
                sendResponse({ password: password });
            })
            .catch(error => {
                console.error("Failed to generate password:", error.name, error.message, error.stack);
                sendResponse({ error: "Password generation failed: " + error.message });
            });
        return true;
    }

    if (request.action === "lock") {
        lockMasterKey();
        sendResponse({ success: true, locked: true });
        return false;
    }

    if (request.action === "getLockState") {
        sendResponse({ locked: masterKeyBinary === null });
        return false;
    }

    if (request.action === "addMapping") {
        addMapping(request.data.domain, request.data.username)
            .then(sendResponse).catch(err => sendResponse({ success: false, error: err.message }));
        return true;
    }

    if (request.action === "removeMapping") {
        removeMapping(request.data.domain, request.data.username)
            .then(sendResponse).catch(err => sendResponse({ success: false, error: err.message }));
        return true;
    }

    if (request.action === "getUsernamesForDomain") {
        getUsernamesForDomain(request.data.domain)
            .then(sendResponse).catch(err => sendResponse({ usernames: [], error: err.message }));
        return true;
    }

    if (request.action === "getAllMappings") {
        getMappings()
            .then(mappings => sendResponse({ mappings }))
            .catch(err => sendResponse({ mappings: {}, error: err.message }));
        return true;
    }



    //updation from here

    if (request.action === "webAuthnStartRegistration") {
        const rpId = chrome.runtime.id;
        const rpName = "CryptoPass Extension";
        const userId = "cryptopass_internal_user_id_fixed"; // Fixed ID for this extension user
        const userName = "CryptoPass User";
        const userDisplayName = "CryptoPass User";

        const challenge = crypto.getRandomValues(new Uint8Array(32));
        
        // For navigator.credentials.create(), the challenge isn't strictly needed to be stored by us
        // if we're not doing server-side attestation validation. The browser handles it.
        // However, for navigator.credentials.get() (authentication), we MUST store and verify the challenge.

        const options = {
            challenge: challenge, // Will be ArrayBuffer/TypedArray
            rp: { id: rpId, name: rpName },
            user: {
                id: Uint8Array.from(userId, c => c.charCodeAt(0)),
                name: userName,
                displayName: userDisplayName,
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
            authenticatorSelection: { userVerification: "preferred", requireResidentKey: false },
            timeout: 60000,
            attestation: "none"
        };
        // //("[WEBAUTHN_REG] Start Registration Options for Popup:", options);
        //sendResponse({ success: true, optionsForCreate: options }); // Send raw options
        sendResponse({ success: true, publicKeyCredentialCreationOptions: options });
        return false;
    }

   
   /*if (request.action === "webAuthnCompleteRegistration") {
        const { createdCredential } = request.data;
        if (!createdCredential || !createdCredential.rawId) {  sendResponse({ success: false, error: "Invalid createdCredential or missing rawId." });  return false; }
        // NOTE: `saveWebAuthnCredentials` (the encrypted one) is only called IF masterKeyBinary is present.
        // Registration ideally happens when unlocked.
        // For simplicity of this "final build", we'll require unlock for registration.
        if (!masterKeyBinary) { sendResponse({ success: false, error: "Unlock to register WebAuthn" }); return false; }
         

        //  //("[BG_WA_REG_COMP] Received createdCredential.rawId (ArrayBuffer/TypedArray):", createdCredential.rawId);
    // Check its byteLength
    if (createdCredential.rawId.byteLength === 0) {
        console.error("[BG_WA_REG_COMP] createdCredential.rawId has byteLength 0! Cannot create valid ID.");
        sendResponse({ success: false, error: "Received an empty credential ID from browser." });
        return false;
    }

         
         const newCredentialIdString = createdCredential.rawId; // Convert the ArrayBuffer rawId

    if (!newCredentialIdString) { // Check if conversion resulted in empty string
        console.error("[BG_WA_REG_COMP] bufferToBase64URL returned an empty string for credential ID.");
        sendResponse({ success: false, error: "Failed to convert credential ID to Base64URL." });
        return false;
    }
        
        const newCredentialIdEntry = { id: bufferToBase64URL(createdCredential.rawId) };
        // //("[BG_WA_REG_COMP] New cred ID entry:", newCredentialIdEntry);

        getWebAuthnCredentialIDs().then(async (existingCredIds) => { // Use unencrypted getter
            if (existingCredIds.some(c => c.id === newCredentialIdEntry.id)) {
                sendResponse({ success: true, message: "Already registered" }); return;
            }
            existingCredIds.push(newCredentialIdEntry);
            const saveIdsResult = await saveWebAuthnCredentialIDs(existingCredIds); // Save unencrypted IDs

            if (saveIdsResult.success) {
                const prefs = await getUnlockPreferences();
                prefs.useWebAuthnUnlock = true;
                prefs.hasRegisteredWebAuthnKeys = true;
                await saveUnlockPreferences(prefs);
                sendResponse({ success: true, message: "WebAuthn registered & enabled." });
            } else {
                sendResponse({ success: false, error: "Failed to save WebAuthn credential ID." });
            }
        }).catch(e => sendResponse({ success: false, error: e.message }));
        return true;
    }*/


    /*if (request.action === "webAuthnCompleteRegistration") {
        // Use request.data to get the payload sent from the popup
        const { createdCredential } = request.data;

        // 1. Log what was received precisely
        // //("[BG_WA_REG_COMP] Received 'createdCredential' object from popup:", JSON.parse(JSON.stringify(createdCredential)));

        // 2. Specifically log the rawId part AS RECEIVED
        if (createdCredential && typeof createdCredential.rawId !== 'undefined') {
            // //("[BG_WA_REG_COMP] 'createdCredential.rawId' AS RECEIVED (type):", typeof createdCredential.rawId);
            // Detailed log of rawId's structure if it's an object but not ArrayBuffer/Uint8Array
            if (typeof createdCredential.rawId === 'object' &&
                !(createdCredential.rawId instanceof ArrayBuffer) &&
                !(createdCredential.rawId instanceof Uint8Array)) {
                // //("[BG_WA_REG_COMP] 'createdCredential.rawId' as plain object:", JSON.parse(JSON.stringify(createdCredential.rawId)));
            } else if (createdCredential.rawId instanceof ArrayBuffer || createdCredential.rawId instanceof Uint8Array) {
                //  //("[BG_WA_REG_COMP] 'createdCredential.rawId' byteLength:", createdCredential.rawId.byteLength);
            }
        } else {
            console.error("[BG_WA_REG_COMP] 'createdCredential' or 'createdCredential.rawId' is undefined/null in request.data.");
        }

        if (!createdCredential || typeof createdCredential.rawId === 'undefined') {
            console.error("[BG_WA_REG_COMP] Invalid: createdCredential or rawId is undefined in the received data.");
            sendResponse({ success: false, error: "Invalid credential data received from popup (missing createdCredential or rawId)." });
            return false; // Synchronous response for this validation failure
        }

        // Registration ideally happens when the main app functionality is unlocked,
        // as some operations (like saving full encrypted credential details if we did that)
        // would require the masterKeyBinary for deriving the storageEncryptionKey.
        // For saving just the UNENCRYPTED ID and UNENCRYPTED preferences, masterKeyBinary is not strictly needed.
        // However, it's a good security practice to ensure the user is "authenticated" (unlocked)
        // before allowing changes like registering a new primary unlock factor.
        if (!masterKeyBinary) {
            console.warn("[BG_WA_REG_COMP] Attempting to register WebAuthn while extension is locked (masterKeyBinary is null). For security, this might be disallowed in future versions.");
            // For now, we allow it to proceed if only saving unencrypted ID & prefs.
            // If you decide to disallow:
            // sendResponse({ success: false, error: "Extension must be unlocked with Master Passphrase to register a new Security Key." });
            // return false;
        }

        // 3. Reconstruct rawId into a Uint8Array if it got serialized during message passing
        const rawIdAsUint8Array = objectToUint8Array_BG(createdCredential.rawId, "BG_createdCredential.rawId");
        // //("[BG_WA_REG_COMP] 'rawIdAsUint8Array' after reconstruction (byteLength):", rawIdAsUint8Array.byteLength);

        if (rawIdAsUint8Array.byteLength === 0) {
            console.error("[BG_WA_REG_COMP] Reconstructed rawId is empty. Original rawId from popup might have been invalid or lost in transit. Original was:", JSON.parse(JSON.stringify(createdCredential.rawId)));
            sendResponse({ success: false, error: "Credential ID from popup became empty after processing in background." });
            return false;
        }

        // 4. Convert the .buffer of the Uint8Array to Base64URL string
        const newCredentialIdString = bufferToBase64URL(rawIdAsUint8Array.buffer); // bufferToBase64URL expects ArrayBuffer

        // 5. Check if the Base64URL string is empty
        if (!newCredentialIdString) {
            console.error("[BG_WA_REG_COMP] bufferToBase64URL returned an empty string. This indicates an issue with buffer conversion or the rawId content (e.g., all zero bytes after reconstruction).");
            sendResponse({ success: false, error: "Failed to convert reconstructed credential ID to a storable string." });
            return false;
        }

        const newIdEntry = { id: newCredentialIdString };
        // //("[BG_WA_REG_COMP] New UNENCRYPTED cred ID entry to save:", newIdEntry);

        getWebAuthnCredentialIDs().then(async (existingCredIds) => {
            if (existingCredIds.some(c => c.id === newIdEntry.id)) {
                // //("[BG_WA_REG_COMP] Credential ID already exists in unencrypted list.");
                sendResponse({ success: true, message: "This security key/method is already registered." });
                return; // Exit before modifying preferences if already registered
            }

            existingCredIds.push(newIdEntry);
            const saveIdsResult = await saveWebAuthnCredentialIDs(existingCredIds); // Saves to UNENCRYPTED_WEBAUTHN_IDS_KEY

            if (saveIdsResult.success) {
                // //("[BG_WA_REG_COMP] Unencrypted credential ID saved successfully.");
                const prefs = await getUnlockPreferences();
                prefs.useWebAuthnUnlock = true;
                prefs.hasRegisteredWebAuthnKeys = true; // Mark that at least one key is now registered
                const savePrefsResult = await saveUnlockPreferences(prefs);

                if (savePrefsResult.success) {
                    // //("[BG_WA_REG_COMP] Unlock preferences updated to enable WebAuthn.");
                    sendResponse({ success: true, message: "WebAuthn authenticator registered and enabled." });
                } else {
                    console.error("[BG_WA_REG_COMP] Credential ID saved, but failed to save unlock preferences.");
                    // Potentially roll back saving the ID if saving preferences is critical, or just warn.
                    sendResponse({ success: false, error: "WebAuthn key registered, but failed to update preferences." });
                }
            } else {
                console.error("[BG_WA_REG_COMP] Failed to save unencrypted credential ID:", saveIdsResult.error);
                sendResponse({ success: false, error: "Failed to save WebAuthn credential ID." });
            }
        }).catch(e => {
            console.error("[BG_WA_REG_COMP] Error in promise chain for saving IDs/prefs:", e);
            sendResponse({ success: false, error: e.message });
        });
        return true; // Indicate async response
    }*/
    
   /* if (request.action === "webAuthnCompleteRegistration") {
        const { createdCredential } = request.data; // data from request.data

        // 1. Log what was received precisely and its type
        // //("[BG_WA_REG_COMP] Received 'createdCredential' object from popup:", JSON.parse(JSON.stringify(createdCredential)));
        
        let rawIdFromPopup = null;
        if (createdCredential && typeof createdCredential.rawId !== 'undefined') {
            rawIdFromPopup = createdCredential.rawId;
            // //("[BG_WA_REG_COMP] 'rawIdFromPopup' AS RECEIVED (type):", typeof rawIdFromPopup);
            // //("[BG_WA_REG_COMP] 'rawIdFromPopup' constructor name:", rawIdFromPopup ? rawIdFromPopup.constructor.name : 'N/A');
            // //("[BG_WA_REG_COMP] 'rawIdFromPopup' byteLength (if applicable):", 
                rawIdFromPopup && typeof rawIdFromPopup.byteLength === 'number' ? rawIdFromPopup.byteLength : 'N/A or not a buffer/view'
            );
            if (typeof rawIdFromPopup === 'object' && rawIdFromPopup !== null && 
                !(rawIdFromPopup instanceof ArrayBuffer) && !(rawIdFromPopup instanceof Uint8Array)) {
                // //("[BG_WA_REG_COMP] 'rawIdFromPopup' as plain object structure:", JSON.parse(JSON.stringify(rawIdFromPopup)));
            }
        } else {
            console.error("[BG_WA_REG_COMP] 'createdCredential' or 'createdCredential.rawId' is undefined/null in request.data.");
        }

        if (!rawIdFromPopup) {
            console.error("[BG_WA_REG_COMP] Invalid: rawIdFromPopup is null or undefined after initial check.");
            sendResponse({ success: false, error: "Invalid credential data (rawId missing or null)." });
            return false;
        }

        // Registration should ideally happen when unlocked, but we allow saving unencrypted ID if not.
        // if (!masterKeyBinary) { console.warn("[BG_WA_REG_COMP] Registering WebAuthn while locked."); }

        // 2. Reconstruct rawId into a Uint8Array
       // const rawIdAsUint8Array = objectToUint8Array_BG(rawIdFromPopup, "BG_createdCredential.rawId");
        const rawIdAsUint8Array = base64URLToBuffer(rawIdFromPopup);
        // //("[BG_WA_REG_COMP] 'rawIdAsUint8Array' after reconstruction (constructor, byteLength):", 
            rawIdAsUint8Array.constructor.name, 
            rawIdAsUint8Array.byteLength
        );
        if (rawIdAsUint8Array.byteLength > 0 && rawIdAsUint8Array.byteLength < 100) {
            // //("[BG_WA_REG_COMP] 'rawIdAsUint8Array' content (first few bytes):", Array.from(rawIdAsUint8Array.slice(0, 16)));
        }

        if (rawIdAsUint8Array.byteLength === 0) {
            console.error("[BG_WA_REG_COMP] Reconstructed rawId is empty. Original rawId from popup was:", JSON.parse(JSON.stringify(rawIdFromPopup)));
            sendResponse({ success: false, error: "Credential ID from popup became empty after processing in background." });
            return false;
        }

        // 3. Convert the Uint8Array to Base64URL string
        const newCredentialIdString = bufferToBase64URL(rawIdAsUint8Array); // Pass Uint8Array directly

        if (!newCredentialIdString) {
            console.error("[BG_WA_REG_COMP] bufferToBase64URL returned an empty string from rawIdAsUint8Array. This implies rawId was all zeros or conversion failed.");
            sendResponse({ success: false, error: "Failed to convert reconstructed credential ID to a storable string." });
            return false;
        }

        const newIdEntry = { id: newCredentialIdString };
        // //("[BG_WA_REG_COMP] New UNENCRYPTED cred ID entry to save:", newIdEntry);

        getWebAuthnCredentialIDs().then(async (existingCredIds) => {
            if (existingCredIds.some(c => c.id === newIdEntry.id)) {
                // //("[BG_WA_REG_COMP] Credential ID already exists in unencrypted list.");
                sendResponse({ success: true, message: "This security key/method is already registered." });
                return;
            }
            existingCredIds.push(newIdEntry);
            const saveIdsResult = await saveWebAuthnCredentialIDs(existingCredIds);

            if (saveIdsResult.success) {
                // //("[BG_WA_REG_COMP] Unencrypted credential ID saved successfully.");
                const prefs = await getUnlockPreferences();
                prefs.useWebAuthnUnlock = true;
                prefs.hasRegisteredWebAuthnKeys = true;
                const savePrefsResult = await saveUnlockPreferences(prefs);
                if (savePrefsResult.success) {
                    // //("[BG_WA_REG_COMP] Unlock preferences updated to enable WebAuthn.");
                    sendResponse({ success: true, message: "WebAuthn authenticator registered and enabled." });
                } else {
                    console.error("[BG_WA_REG_COMP] Credential ID saved, but failed to save unlock preferences.");
                    sendResponse({ success: false, error: "WebAuthn key registered, but failed to update preferences." });
                }
            } else {
                console.error("[BG_WA_REG_COMP] Failed to save unencrypted credential ID:", saveIdsResult.error);
                sendResponse({ success: false, error: "Failed to save WebAuthn credential ID." });
            }
        }).catch(e => {
            console.error("[BG_WA_REG_COMP] Error in promise chain for saving IDs/prefs:", e);
            sendResponse({ success: false, error: e.message });
        });
        return true; // Indicate async response
    }*/

      if (request.action === "webAuthnCompleteRegistration") {
        const { createdCredential } = request.data;

        // 1. Log what was received. The `rawId` should already be a Base64URL string.
        // //("[BG_WA_REG_COMP] Received 'createdCredential' object from popup:", JSON.parse(JSON.stringify(createdCredential)));

        // 2. Directly get the pre-converted Base64URL string from the payload.
        const newCredentialIdString = createdCredential ? createdCredential.rawId : null;
        
        // //("[BG_WA_REG_COMP] 'rawId' as received (should be Base64URL string):", newCredentialIdString);

        // 3. Validate that the received string is valid and non-empty.
        // This is the CRITICAL check that prevents an empty ID from being saved.
        if (!newCredentialIdString || typeof newCredentialIdString !== 'string' || newCredentialIdString.trim() === '') {
            console.error("[BG_WA_REG_COMP] Invalid or empty credential ID string received from popup.", newCredentialIdString);
            sendResponse({ success: false, error: "Invalid credential ID received from popup. It was empty or not a string." });
            return false; // Stop execution
        }

        // 4. Create the entry for storage. We no longer need to decode/re-encode the ID.
        const newIdEntry = { id: newCredentialIdString.trim() }; // Trim for safety
        // //("[BG_WA_REG_COMP] New UNENCRYPTED cred ID entry to save:", newIdEntry);

        getWebAuthnCredentialIDs().then(async (existingCredIds) => {
            if (existingCredIds.some(c => c.id === newIdEntry.id)) {
                // //("[BG_WA_REG_COMP] Credential ID already exists in unencrypted list.");
                sendResponse({ success: true, message: "This security key/method is already registered." });
                return;
            }

            existingCredIds.push(newIdEntry);
            const saveIdsResult = await saveWebAuthnCredentialIDs(existingCredIds);

            if (saveIdsResult.success) {
                // //("[BG_WA_REG_COMP] Unencrypted credential ID saved successfully.");
                const prefs = await getUnlockPreferences();
                prefs.useWebAuthnUnlock = true;
                prefs.hasRegisteredWebAuthnKeys = true;
                const savePrefsResult = await saveUnlockPreferences(prefs);
                
                if (savePrefsResult.success) {
                    // //("[BG_WA_REG_COMP] Unlock preferences updated to enable WebAuthn.");
                    sendResponse({ success: true, message: "WebAuthn authenticator registered and enabled." });
                } else {
                    console.error("[BG_WA_REG_COMP] Credential ID saved, but failed to save unlock preferences.");
                    // In a real-world scenario, you might want to roll back the ID save here.
                    sendResponse({ success: false, error: "WebAuthn key registered, but failed to update preferences." });
                }
            } else {
                console.error("[BG_WA_REG_COMP] Failed to save unencrypted credential ID:", saveIdsResult.error);
                sendResponse({ success: false, error: "Failed to save WebAuthn credential ID." });
            }
        }).catch(e => {
            console.error("[BG_WA_REG_COMP] Error in promise chain for saving IDs/prefs:", e);
            sendResponse({ success: false, error: e.message });
        });

        return true; // Indicate that the response will be sent asynchronously.
    }
   


    /*if (request.action === "webAuthnStartAuthentication") {
        getWebAuthnCredentials().then(storedCredentials => {
            if (!storedCredentials || storedCredentials.length === 0) {
                sendResponse({ success: false, error: "No WebAuthn keys registered for unlock." });
                return;
            }
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            currentWebAuthnChallengeForAuth = bufferToBase64URL(challenge); // Store Base64URL for comparison

            const allowCredentials = storedCredentials.map(cred => ({
                type: "public-key",
                id: base64URLToBuffer(cred.id) // Convert stored Base64URL ID back to ArrayBuffer
            }));

            const options = {
                challenge: challenge, // Pass raw ArrayBuffer challenge
                allowCredentials: allowCredentials,
                userVerification: "preferred", // Or "required" if you want to enforce biometrics/PIN always
                timeout: 60000,
                rpId: chrome.runtime.id // Important for scoped credentials
            };
            // //("[WEBAUTHN_AUTH] Start Authentication Options for Popup:", options);
            sendResponse({ success: true, optionsForGet: options });
        }).catch(err => sendResponse({ success: false, error: `Failed to get credentials for auth: ${err.message}`}));
        return true; // Async
    }*/
    if (request.action === "webAuthnStartAuthentication") {
        // This can be called when the app IS locked.
        getUnlockPreferences().then(prefs => {
            if (!prefs.useWebAuthnUnlock || !prefs.hasRegisteredWebAuthnKeys) {
                sendResponse({ success: false, error: "WebAuthn not preferred or no keys." }); return;
            }
            getWebAuthnCredentialIDs().then(allowCredsList => { // Get UNENCRYPTED IDs
                if (!allowCredsList || allowCredsList.length === 0) {
                     sendResponse({ success: false, error: "No WebAuthn keys found (unencrypted list)." }); return;
                }
                const challenge = crypto.getRandomValues(new Uint8Array(32));
                currentWebAuthnChallengeForAuth = bufferToBase64URL(challenge);
               /* const options = {
                    challenge,
                    allowCredentials: allowCredsList.map(c => ({ type: "public-key", id: base64URLToBuffer(c.id) })),
                    userVerification: "preferred", timeout: 60000, rpId: chrome.runtime.id
                };*/

                const allowCredentials = allowCredsList.map(c => ({
                type: "public-key",
               // id: base64URLToBuffer(c.id)
                id: c.id 
            }));

            // //("[BG_WA_AUTH_START] Credential IDs from storage (Base64URL):", JSON.stringify(allowCredsList));
// //("[BG_WA_AUTH_START] `allowCredentials` being prepared for API (first entry's ID as ArrayBuffer):", allowCredentials[0] ? allowCredentials[0].id : "No creds");
                const options = {
                challenge: challenge, // Pass raw ArrayBuffer challenge
                allowCredentials: allowCredentials,
                userVerification: "required", // Or "required" if you want to enforce biometrics/PIN always
                timeout: 60000,
                rpId: chrome.runtime.id // Important for scoped credentials
            };
                // //("[BG_WA_AUTH_START] Options for popup:", options);
                sendResponse({ success: true, optionsForGet: options });
            }).catch(e => sendResponse({success: false, error: "Failed to get allowCredentials: " + e.message}));
        }).catch(e => sendResponse({ success: false, error: "Failed to get prefs for auth: " + e.message}));
        return true;
    }

    /*if (request.action === "webAuthnCompleteAuthentication") {
        const { assertion } = request.data; // assertion is a PublicKeyCredential
        if (!assertion || !assertion.response || !assertion.response.clientDataJSON || !assertion.rawId) {
            sendResponse({ success: false, error: "Invalid WebAuthn assertion received." }); return false;
        }

        const clientDataJSON = JSON.parse(new TextDecoder().decode(assertion.response.clientDataJSON));
        // //("[WEBAUTHN_AUTH] ClientDataJSON from assertion:", clientDataJSON);

        // **1. Verify Challenge**
        if (clientDataJSON.challenge !== currentWebAuthnChallengeForAuth) {
            console.error("[WEBAUTHN_AUTH] Challenge mismatch! Expected:", currentWebAuthnChallengeForAuth, "Got:", clientDataJSON.challenge);
            sendResponse({ success: false, error: "WebAuthn challenge mismatch." });
            currentWebAuthnChallengeForAuth = null; // Clear used challenge
            return false;
        }
        currentWebAuthnChallengeForAuth = null; // Clear used challenge

        // **2. Verify Origin** (for extensions, type is 'chrome-extension://<extension-id>')
        const expectedOrigin = `chrome-extension://${chrome.runtime.id}`;
        if (clientDataJSON.origin !== expectedOrigin) {
            console.error("[WEBAUTHN_AUTH] Origin mismatch! Expected:", expectedOrigin, "Got:", clientDataJSON.origin);
            sendResponse({ success: false, error: "WebAuthn origin mismatch." });
            return false;
        }

        // **3. Verify Credential ID is one we know (optional but good practice)**
        // The browser usually handles this if `allowCredentials` was used in `get()`.
        // const receivedCredId = bufferToBase64URL(assertion.rawId);
        // getWebAuthnCredentials().then(storedCredentials => {
        //     if (!storedCredentials.some(c => c.id === receivedCredId)) {
        //         sendResponse({ success: false, error: "Unknown credential ID." }); return;
        //     }
        //     // Further signature verification could be done here if we stored public keys.
        //     // For client-side "gate" model, success of navigator.credentials.get() with matching
        //     // challenge and origin is often sufficient.
        //     sendResponse({ success: true, message: "WebAuthn authentication successful." });
        // });
        // For simplicity, if challenge and origin match, we'll consider it successful for this "gate" model.
        // The browser and authenticator ensure the signature was valid for the given credential ID.

        // //("[WEBAUTHN_AUTH] WebAuthn Authentication successful (challenge & origin verified).");
        sendResponse({ success: true, message: "WebAuthn authentication successful." });
        return false; // Synchronous for now, could be async if fetching stored pubkeys for sig verify
    }*/
   if (request.action === "webAuthnCompleteAuthentication") {
        const { assertion } = request.data; // This is now the serializableAssertion object
        if (!assertion || !assertion.response || !assertion.response.clientDataJSON || !assertion.rawId) {
            sendResponse({ success: false, error: "Invalid WebAuthn assertion received." });
            return false;
        }

        try {
            // --- NEW: Decode the Base64URL strings back into buffers ---
            const clientDataJSONBuffer = base64URLToBuffer(assertion.response.clientDataJSON);

            // Now use the decoded buffer
            const clientDataJSON = JSON.parse(new TextDecoder().decode(clientDataJSONBuffer));
            // //("[WEBAUTHN_AUTH] ClientDataJSON from assertion:", clientDataJSON);

            // **1. Verify Challenge**
            if (clientDataJSON.challenge !== currentWebAuthnChallengeForAuth) {
                console.error("[WEBAUTHN_AUTH] Challenge mismatch! Expected:", currentWebAuthnChallengeForAuth, "Got:", clientDataJSON.challenge);
                sendResponse({ success: false, error: "WebAuthn challenge mismatch." });
                currentWebAuthnChallengeForAuth = null; // Clear used challenge
                return false;
            }
            currentWebAuthnChallengeForAuth = null; // Clear used challenge, success or fail

            // **2. Verify Origin**
            const expectedOrigin = `chrome-extension://${chrome.runtime.id}`;
            if (clientDataJSON.origin !== expectedOrigin) {
                console.error("[WEBAUTHN_AUTH] Origin mismatch! Expected:", expectedOrigin, "Got:", clientDataJSON.origin);
                sendResponse({ success: false, error: "WebAuthn origin mismatch." });
                return false;
            }

            // For this project's "gate" model, verifying the challenge and origin is sufficient.
            // A full RP server would also verify the signature using the stored public key.

            // //("[WEBAUTHN_AUTH] WebAuthn Authentication successful (challenge & origin verified).");
            sendResponse({ success: true, message: "WebAuthn authentication successful." });

        } catch (err) {
            console.error("[WEBAUTHN_AUTH] Error during verification:", err);
            sendResponse({ success: false, error: `Verification failed: ${err.message}` });
        }
        return false; // We are handling the response synchronously within this block
    }

   

      if (request.action === "getUnlockMethodPreference") {
        getUnlockPreferences().then(prefs => {
            // //("[BG_UNLOCK_PREF] Fetched unencrypted prefs:", JSON.stringify(prefs));
            // We also need to know if any keys *actually* exist.
            // The `hasRegisteredWebAuthnKeys` flag in unencrypted prefs handles this.
            if (prefs && prefs.useWebAuthnUnlock && prefs.hasRegisteredWebAuthnKeys) {
                // //("[BG_UNLOCK_PREF] Sending 'webauthn'.");
                sendResponse({ unlockMethod: "webauthn" });
            } else {
                // //("[BG_UNLOCK_PREF] Defaulting to 'master_passphrase'.");
                sendResponse({ unlockMethod: "master_passphrase" });
            }
        }).catch(e => sendResponse({ unlockMethod: "master_passphrase", error: e.message }));
        return true;
    }   



});






// --- Extension Lifecycle ---
chrome.runtime.onInstalled.addListener(() => {
    // //("CryptoPass extension installed or updated.");
});
