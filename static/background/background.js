/*// background/background.js
console.log("CryptoPass Background Service Worker Started.");

// We'll move password generation logic here later.
// For now, let's listen for messages from the popup (will add soon).
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("Message received in background:", request);

    if (request.action === "getDomain") {
        // Get the current active tab to extract its domain
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs && tabs.length > 0 && tabs[0].url) {
                try {
                    const url = new URL(tabs[0].url);
                    sendResponse({ domain: url.hostname });
                } catch (e) {
                    console.error("Error parsing URL for domain:", e);
                    sendResponse({ domain: null, error: "Invalid URL" });
                }
            } else {
                sendResponse({ domain: null, error: "No active tab or URL found" });
            }
        });
        return true; // Indicates that sendResponse will be called asynchronously
    }

    // Placeholder for password generation later
    if (request.action === "generatePassword") {
        // In a real scenario, we'd use the master key, etc.
        // For now, just echoing back inputs.
        const { domain, username, otop } = request.data;
        const mockPassword = `mockpass_for_${domain}_${username}_${otop}`;
        console.log("Mock password generated:", mockPassword);
        sendResponse({ password: mockPassword });
        return true; // Async if real generation takes time
    }
});

// Example: Listen for when the extension is installed/updated
chrome.runtime.onInstalled.addListener(() => {
    console.log("CryptoPass extension installed or updated.");
    // You could set up default settings here if needed
});*/








// static/background/background.js
// IMPORTANT: Node.js 'crypto' module is not directly available here like in Phase 1.
// Browser extensions use the Web Crypto API: `crypto.subtle`
// For HMAC, it's a bit more involved than node's crypto.createHmac.

console.log("CryptoPass Background Service Worker Started.");

/**
 * Generates a password using HMAC-SHA256 with Web Crypto API.
 * @param {string} keyMaterialString - The string to use as key material (e.g., master passphrase).
 * @param {string} domain - The domain name.
 * @param {string} username - The username.
 * @param {string} otop - The OTOP.
 * @returns {Promise<string>} The generated password, Base64 encoded.
 */
async function generatePasswordWithWebCrypto(keyMaterialString, domain, username, otop) {
    try {
        const dataToHash = `${domain.toLowerCase()}${username}${otop}`;
        const encoder = new TextEncoder();

        // 1. Import the key material (string) into a CryptoKey object
        // We use the keyMaterialString directly as if it's the raw key.
        // In reality, this would be the output of Argon2.
        const keyData = encoder.encode(keyMaterialString); // Convert string to Uint8Array
        const cryptoKey = await crypto.subtle.importKey(
            "raw",          // Format of the key_data
            keyData,        // The key material as Uint8Array
            { name: "HMAC", hash: "SHA-256" }, // Algorithm details
            false,          // Not extractable
            ["sign"]        // Key usages: "sign" for HMAC
        );

        // 2. Sign (HMAC) the data
        const signature = await crypto.subtle.sign(
            "HMAC",
            cryptoKey,
            encoder.encode(dataToHash) // Data to HMAC, also as Uint8Array
        );

        // 3. Convert ArrayBuffer signature to Base64 string
        const signatureBytes = new Uint8Array(signature);
        let base64String = btoa(String.fromCharCode(...signatureBytes)); // Standard Base64
        // Make it URL-safe if needed, or stick to standard for now
        // base64String = base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        return base64String;

    } catch (error) {
        console.error("Error in generatePasswordWithWebCrypto:", error);
        throw error; // Re-throw to be caught by the message listener
    }
}


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("Message received in background:", request);

    if (request.action === "getDomain") {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (chrome.runtime.lastError) { // Check for errors from chrome.tabs.query
                console.error("Error querying tabs:", chrome.runtime.lastError.message);
                sendResponse({ domain: null, error: "Error querying tabs" });
                return;
            }
            if (tabs && tabs.length > 0 && tabs[0].url) {
                try {
                    const url = new URL(tabs[0].url);
                    // Don't send back for chrome:// or about: URLs
                    if (url.protocol === "http:" || url.protocol === "https:") {
                        sendResponse({ domain: url.hostname });
                    } else {
                        sendResponse({ domain: null, note: "Not a web page" });
                    }
                } catch (e) {
                    console.error("Error parsing URL for domain:", e);
                    sendResponse({ domain: null, error: "Invalid URL" });
                }
            } else {
                sendResponse({ domain: null, error: "No active tab or URL found" });
            }
        });
        return true;
    }

    if (request.action === "generatePassword") {
        const { masterPassphrase, domain, username, otop } = request.data;

        if (!masterPassphrase || !domain || !otop) {
            sendResponse({ error: "Missing required fields for password generation." });
            return false; // synchronous response
        }

        // Use the Web Crypto version
        generatePasswordWithWebCrypto(masterPassphrase, domain, username, otop)
            .then(password => {
                console.log("WebCrypto Password generated:", password);
                sendResponse({ password: password });
            })
            .catch(error => {
                console.error("Failed to generate password with WebCrypto:", error);
                sendResponse({ error: "Password generation failed: " + error.message });
            });
        return true; // Indicates that sendResponse will be called asynchronously
    }
});

chrome.runtime.onInstalled.addListener(() => {
    console.log("CryptoPass extension installed or updated.");
});