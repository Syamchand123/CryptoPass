// passwordGenerator.js
const crypto = require('node:crypto'); // Node.js built-in crypto module
const argon2 = require('argon2');     // Argon2 library we installed

// Configuration for Argon2id (these are reasonable defaults)
const argon2Options = {
    type: argon2.argon2id, // Specify Argon2id variant
    memoryCost: 2 ** 16,   // 65536 KiB (64 MiB)
    hashLength: 32,        // Desired key length in bytes (32 bytes = 256 bits)
    timeCost: 3,           // Number of iterations
    parallelism: 1,        // How many threads to use
    // salt: crypto.randomBytes(16) // A unique salt should be generated for EACH master passphrase storage.
                                  // For *deriving* a key deterministically (like here), we DON'T use a random salt
                                  // if the passphrase is the only input. If we were storing a hash of the passphrase,
                                  // we would. For our purpose, the master passphrase *is* the secret, and we derive
                                  // the Master_Key_Binary from it directly.
};

/**
 * Derives a Master Key (binary) from a master passphrase using Argon2id.
 * @param {string} masterPassphrase - The user's master passphrase.
 * @returns {Promise<Buffer>} A promise that resolves to the derived binary key.
 */
async function deriveMasterKey(masterPassphrase) {
    try {
        // Note: For direct key derivation where the passphrase *is* the secret,
        // we don't use a separate random salt because we want the derivation to be deterministic
        // given the same passphrase. The passphrase itself provides the necessary uniqueness.
        // A salt is typically used when *hashing* a password for storage and verification,
        // not for deriving a symmetric key meant to be regenerated on the fly.
        // If you were to *store* an encrypted version of this key, then that encryption would need a salt/IV.
        const derivedKey = await argon2.hash(masterPassphrase, {
            ...argon2Options,
            raw: true, // Output raw binary key
            // No salt needed here for deterministic derivation from the passphrase itself.
            // The passphrase acts as the primary secret.
        });
        return derivedKey;
    } catch (err) {
        console.error("Error deriving master key:", err);
        throw err; // Re-throw the error to be handled by the caller
    }
}

/**
 * Generates a password using HMAC-SHA256.
 * @param {Buffer} masterKeyBinary - The derived binary master key.
 * @param {string} domain - The domain name (e.g., "gmail.com").
 * @param {string} username - The username for the account.
 * @param {string} otop - The One-Time Cryptographic Password.
 * @returns {string} The generated password, Base64 encoded.
 */
function generatePassword(masterKeyBinary, domain, username, otop) {
    if (!masterKeyBinary || masterKeyBinary.length === 0) {
        throw new Error("Master key cannot be empty.");
    }
    const dataToHash = `${domain.toLowerCase()}${username}${otop}`; // Concatenate inputs. Normalize domain.
    const hmac = crypto.createHmac('sha256', masterKeyBinary);
    hmac.update(dataToHash);
    return hmac.digest('base64'); // Output as Base64 string
}

// Export the functions so they can be used in other files
module.exports = {
    deriveMasterKey,
    generatePassword
};

// --- Quick Test (can be run directly with `node passwordGenerator.js`) ---
async function mainTest() {
    console.log("Running CLI prototype test...\n");

    const testMasterPassphrase = "SuperSecretPassword123!";
    const testDomain = "example.com";
    const testUsername = "user@example.com";
    const testOtop = "A7#x9!pL2"; // Your example OTOP

    try {
        console.log(`Deriving master key from passphrase: "${testMasterPassphrase}"`);
        const masterKey = await deriveMasterKey(testMasterPassphrase);
        console.log("Master Key (hex):", masterKey.toString('hex')); // Don't log actual keys in production
        console.log("Master Key Length (bytes):", masterKey.length);

        console.log(`\nGenerating password for:`);
        console.log(`  Domain: ${testDomain}`);
        console.log(`  Username: ${testUsername}`);
        console.log(`  OTOP: ${testOtop}`);

        const password = generatePassword(masterKey, testDomain, testUsername, testOtop);
        console.log("\nGenerated Password (Base64):", password);

        // Test determinism: run it again with same inputs
        const masterKey2 = await deriveMasterKey(testMasterPassphrase);
        const password2 = generatePassword(masterKey2, testDomain, testUsername, testOtop);
        console.log("Generated Password (2nd time):", password2);
        console.log("Passwords match:", password === password2);

        // Test with slightly different OTOP
        const password3 = generatePassword(masterKey, testDomain, testUsername, "differentOTOP");
        console.log("\nGenerated Password (different OTOP):", password3);
        console.log("Passwords different (expected):", password !== password3);

    } catch (err) {
        console.error("\nError during test:", err);
    }
}

// This allows running the test directly if the script is executed,
// but doesn't run when `require`d by another script.
if (require.main === module) {
    mainTest();
}