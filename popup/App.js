
// popup/App.js
import React, { useState, useEffect, useCallback, useRef } from 'react';

// Helper to reconstruct Uint8Array from a serialized object (e.g., after chrome.runtime.sendMessage)



function App() {
    // --- Core States ---
    const [masterPassphrase, setMasterPassphrase] = useState('');
    const [domain, setDomain] = useState('');
    const [username, setUsername] = useState('');
    const [otop, setOtop] = useState('');
    const [generatedPassword, setGeneratedPassword] = useState('');

    // --- UI/Flow Control States ---
    const [isLoading, setIsLoading] = useState(true); // Start true for initial load
    const [isAppLocked, setIsAppLocked] = useState(true);
    const [error, setError] = useState('');
    const [statusMessage, setStatusMessage] = useState(''); // General status

    // --- Username Mapping States ---
    const [currentDomainUsernames, setCurrentDomainUsernames] = useState([]);
    const [selectedUsername, setSelectedUsername] = useState('');

    // --- WebAuthn States ---
    const [unlockMethod, setUnlockMethod] = useState('loading'); // 'loading', 'webauthn', 'master_passphrase'
    const [webAuthnVerifiedThisSession, setWebAuthnVerifiedThisSession] = useState(false);
    const [webAuthnStatus, setWebAuthnStatus] = useState(''); // WebAuthn specific status/guidance
    // const [isWebAuthnAvailableAndEnabled, setIsWebAuthnAvailableAndEnabled] = useState(false); // Derived from unlockMethod

    // --- Refs ---
    const masterPassphraseInputRef = useRef(null);

    // --- Stable Callbacks ---
    const clearMessages = useCallback((clearAll = false) => {
        setError('');
        setWebAuthnStatus('');
        if (clearAll) setStatusMessage('');
    }, []);

    const fetchUsernamesForCurrentDomain = useCallback(() => {
        if (domain && !isAppLocked && chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({ action: "getUsernamesForDomain", data: { domain } }, (response) => {
                if (chrome.runtime.lastError) { console.error("Popup: Error fetching usernames (runtime):", chrome.runtime.lastError.message); setCurrentDomainUsernames([]); setError("Could not fetch accounts."); return; }
                if (response) {
                    if (response.error) { console.error("Popup: Error fetching usernames (API):", response.error); setCurrentDomainUsernames([]); setError(response.error.includes("decrypt") ? "Failed to load accounts. Key/data issue." : `Error: ${response.error}`); }
                    else if (response.usernames) { setCurrentDomainUsernames(response.usernames); }
                } else { setCurrentDomainUsernames([]); setError("No response for accounts."); }
            });
        } else { setCurrentDomainUsernames([]); }
    }, [domain, isAppLocked]);


    const initializeAppStates = useCallback(() => {
      // console.log("Popup: Initializing app states...");
        clearMessages(true);
        setIsLoading(true);
        setGeneratedPassword('');

        if (chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({ action: "getLockState" }, (lockStateResponse) => {
                setIsLoading(false);
                if (chrome.runtime.lastError) {
                    setError("Error initializing: " + chrome.runtime.lastError.message);
                    setIsAppLocked(true); setUnlockMethod("master_passphrase"); setStatusMessage("Locked. Enter Master Passphrase.");
                    setTimeout(() => masterPassphraseInputRef.current?.focus(), 0); return;
                }
                if (lockStateResponse) {
                    setIsAppLocked(lockStateResponse.locked);
                    if (lockStateResponse.locked) {
                        setMasterPassphrase(''); setWebAuthnVerifiedThisSession(false);
                        chrome.runtime.sendMessage({ action: "getUnlockMethodPreference" }, (prefResponse) => {
                            if (chrome.runtime.lastError) {
                                setError("Error getting unlock preference."); setUnlockMethod("master_passphrase");
                                setStatusMessage("Locked. Enter Master Passphrase."); setTimeout(() => masterPassphraseInputRef.current?.focus(), 0); return;
                            }
                            if (prefResponse) {
                                const preferredMethod = prefResponse.unlockMethod || "master_passphrase";
                                setUnlockMethod(preferredMethod);
                                if (preferredMethod === "webauthn") { setStatusMessage("Ready for Security Key unlock."); }
                                else { setStatusMessage("Locked. Enter Master Passphrase."); setTimeout(() => masterPassphraseInputRef.current?.focus(), 0); }
                            } else { setUnlockMethod("master_passphrase"); setStatusMessage("Locked. Enter Master Passphrase."); setTimeout(() => masterPassphraseInputRef.current?.focus(), 0); }
                        });
                    } else {
                        setUnlockMethod("master_passphrase"); setWebAuthnVerifiedThisSession(true); // Assume MP was used if already unlocked
                        setStatusMessage("Unlocked."); fetchUsernamesForCurrentDomain();
                    }
                } else { setIsAppLocked(true); setUnlockMethod("master_passphrase"); setStatusMessage("Locked. Enter Master Passphrase."); setTimeout(() => masterPassphraseInputRef.current?.focus(), 0); }
            });
        } else { setIsLoading(false); setIsAppLocked(true); setUnlockMethod("master_passphrase"); setStatusMessage("Locked. Enter Master Passphrase."); setTimeout(() => masterPassphraseInputRef.current?.focus(), 0); }
    }, [clearMessages, fetchUsernamesForCurrentDomain]);

    // --- Effects ---
    useEffect(() => { // Initialize on mount and listen for background lock updates
        initializeAppStates();
        if (chrome.runtime && chrome.runtime.onMessage) {
            const messageListener = (message) => {
                if (message.action === "updateLockState" && message.locked) {
                    // console.log("Popup: Received background lock update.");
                    initializeAppStates(); // Re-initialize fully
                }
            };
            chrome.runtime.onMessage.addListener(messageListener);
            return () => chrome.runtime.onMessage.removeListener(messageListener);
        }
    }, [initializeAppStates]); // initializeAppStates is stable

    useEffect(() => { // Fetch current tab's domain on mount
        // console.log("Popup: Fetching domain on mount.");
        if (chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({ action: "getDomain" }, (response) => {
                if (chrome.runtime.lastError) { console.error("Popup: Error getting domain (runtime):", chrome.runtime.lastError.message); setDomain(''); return; }
                if (response) {
                    if (response.domain) { setDomain(response.domain); }
                    else { setDomain('');
                        // console.log("Popup: No domain from background.", response.note || response.error); 
                        }
                } else { setDomain(''); }
            });
        } else { setDomain("dev.example.com"); }
    }, []);

    useEffect(() => { // Fetch usernames when app is unlocked and domain is known
        if (!isAppLocked && domain) {
             fetchUsernamesForCurrentDomain();
        } else {
            setCurrentDomainUsernames([]);
        }
    }, [isAppLocked, domain, fetchUsernamesForCurrentDomain]);


    // --- Event Handlers ---
    const handleAddMapping = () => {
        clearMessages();
        if (!domain) { setError("Domain is missing."); return; }
        if (!username) { setError("Username is missing to add mapping."); return; }
        setStatusMessage('Adding mapping...'); setIsLoading(true);
        chrome.runtime.sendMessage( { action: "addMapping", data: { domain, username } }, (response) => {
            setIsLoading(false);
            if (chrome.runtime.lastError) { setError(`Error adding: ${chrome.runtime.lastError.message}`); setStatusMessage(''); return; }
            if (response && response.success) { setStatusMessage(`Account saved: ${username} @ ${domain}`); fetchUsernamesForCurrentDomain(); }
            else { setError(response.error || "Failed to add (likely exists)."); setStatusMessage(''); }
        });
    };

    const handleRemoveMapping = (userToRemove) => {
        clearMessages();
        if (!domain || !userToRemove) return;
        setStatusMessage(`Removing ${userToRemove}...`); setIsLoading(true);
        chrome.runtime.sendMessage( { action: "removeMapping", data: { domain, username: userToRemove } }, (response) => {
            setIsLoading(false);
            if (chrome.runtime.lastError) { setError(`Error removing: ${chrome.runtime.lastError.message}`); setStatusMessage(''); return; }
            if (response && response.success) { setStatusMessage(`Account removed: ${userToRemove} @ ${domain}`); if (selectedUsername === userToRemove) { setSelectedUsername(''); setUsername(''); } fetchUsernamesForCurrentDomain(); }
            else { setError(response.error || `Failed to remove.`); setStatusMessage(''); }
        });
    };

    const handleUsernameSelectionChange = (e) => {
        const newSelectedUser = e.target.value;
        setSelectedUsername(newSelectedUser); setUsername(newSelectedUser); clearMessages();
    };

    function bufferToBase64URL(buffer) {
    // Convert ArrayBuffer to Uint8Array if needed
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

    const handleRegisterWebAuthn = async () => {
        clearMessages();
        if (isAppLocked) { setError("Unlock with Master Passphrase first to manage Security Keys."); return; }
        setWebAuthnStatus('Starting Security Key registration...'); setIsLoading(true);
        chrome.runtime.sendMessage({ action: "webAuthnStartRegistration" }, async (response) => {
            setIsLoading(false);
            if (chrome.runtime.lastError || !response || !response.success) { setError(`Reg start error: ${chrome.runtime.lastError?.message || response?.error || 'Unknown'}`); setWebAuthnStatus(''); return; }
            setWebAuthnStatus('Browser prompt for Security Key should appear...');
           /* try {
                const opts = response.optionsForCreate;
                const createOptions = {
                    ...opts,
                    challenge: objectToUint8Array(opts.challenge, "reg_challenge"),
                    user: { ...opts.user, id: objectToUint8Array(opts.user.id, "reg_user.id") },
                };*/
                try {
    const opts = response.publicKeyCredentialCreationOptions;
    if (!opts || !opts.challenge || !opts.user || !opts.user.id) {
        throw new Error("Registration options missing or malformed from background.");
    }
    const createOptions = {
        ...opts,
        challenge: objectToUint8Array(opts.challenge, "reg_challenge"),
        user: { ...opts.user, id: objectToUint8Array(opts.user.id, "reg_user.id") },
    };
    // ...
                if (createOptions.challenge.length < 16) throw new Error("Reconstructed challenge too short for registration.");
                

                // console.log("Popup [WA_REG]: Final PublicKeyCredentialCreationOptions for navigator:", createOptions);
                setIsLoading(true);
                const credential = await navigator.credentials.create({ publicKey: createOptions });

                //  console.log("Popup [WA_REG]: Credential object from navigator.credentials.create():", credential);
                // console.log("Popup [WA_REG]: credential.rawId (ArrayBuffer):", credential.rawId);
                // console.log("Popup [WA_REG]: credential.rawId.byteLength:", credential.rawId ? credential.rawId.byteLength : "rawId is null/undefined");
                 
                const credentialToSend = {
    id: credential.id,
    rawId: bufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
        clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
        attestationObject: bufferToBase64URL(credential.response.attestationObject),
    }
};
                setWebAuthnStatus('Security Key responded. Completing registration...');
                /*chrome.runtime.sendMessage( { action: "webAuthnCompleteRegistration", data: { createdCredential: credential } }, (completeResponse) => {
                    setIsLoading(false);
                    if (chrome.runtime.lastError || !completeResponse || !completeResponse.success) { setError(`Reg complete error: ${chrome.runtime.lastError?.message || completeResponse?.error || 'Unknown'}`); setWebAuthnStatus(''); }
                    else { setWebAuthnStatus(completeResponse.message || 'Security Key registered!'); setUnlockMethod("webauthn");  }
                });*/
                chrome.runtime.sendMessage(
    { action: "webAuthnCompleteRegistration", data: { createdCredential: credentialToSend } },
    (completeResponse) => {
        setIsLoading(false);
        if (chrome.runtime.lastError || !completeResponse || !completeResponse.success) {
            setError(`Reg complete error: ${chrome.runtime.lastError?.message || completeResponse?.error || 'Unknown'}`);
            setWebAuthnStatus('');
        } else {
            setWebAuthnStatus(completeResponse.message || 'Security Key registered!');
            setUnlockMethod("webauthn");
        }
    }
);
            } catch (err) { setError(`Security Key reg failed: ${err.message || err.name}`); setWebAuthnStatus(''); setIsLoading(false); }
        });
    };

    /*const objectToUint8Array = (obj, fieldName = "UnknownField") => {
    if (!obj) {
        console.warn(`Popup: Field '${fieldName}' is null or undefined in objectToUint8Array.`);
        return new Uint8Array(0); // Return empty, let WebAuthn API validate if it's truly required
    }
    if (obj instanceof Uint8Array) {
        console.log(`Popup: Field '${fieldName}' is already Uint8Array.`);
        return obj;
    }
    // Check if it's an Array-like object (e.g., {0: byte, 1: byte, length: 2})
    if (typeof obj === 'object' && obj !== null && typeof obj.length === 'number') {
        const arr = new Uint8Array(obj.length);
        for (let i = 0; i < obj.length; i++) {
            arr[i] = obj[i] || 0; // Default to 0 if a specific index is missing
        }
        // console.log(`Popup: Reconstructed Uint8Array for field '${fieldName}' from array-like object. Length: ${arr.length}`);
        return arr;
    }
    // Check if it's an object with numeric keys (less reliable for length)
    if (typeof obj === 'object' && obj !== null) {
        const numericKeys = Object.keys(obj).map(Number).filter(k => !isNaN(k) && k >= 0).sort((a, b) => a - b);
        if (numericKeys.length > 0 && numericKeys.every((k, i) => k === i)) { // Dense, 0-indexed
            const arr = new Uint8Array(numericKeys.length);
            for (let i = 0; i < numericKeys.length; i++) {
                arr[i] = obj[i] || 0;
            }
            // console.log(`Popup: Reconstructed Uint8Array for field '${fieldName}' from dense object. Length: ${arr.length}`);
            return arr;
        }
    }
    console.error(`Popup: Failed to convert field '${fieldName}' to Uint8Array. Received type: ${typeof obj}, value:`, JSON.parse(JSON.stringify(obj)));
    return new Uint8Array(0); // Return empty as a fallback
};*/
  
const objectToUint8Array = (obj, fieldName = "UnknownField") => {
    if (!obj) {
        console.warn(`Popup: Field '${fieldName}' is null or undefined in objectToUint8Array.`);
        return new Uint8Array(0);
    }
    if (obj instanceof Uint8Array) return obj;
    if (obj instanceof ArrayBuffer) return new Uint8Array(obj);
    if (typeof obj === "string") {
        // Assume base64url string
        let base64 = obj.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) base64 += '=';
        const binary = atob(base64);
        const arr = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
        return arr;
    }
    // Handle array-like objects (e.g., {0:..., 1:..., length:...})
    if (typeof obj === 'object' && obj !== null && typeof obj.length === 'number') {
        const arr = new Uint8Array(obj.length);
        for (let i = 0; i < obj.length; i++) arr[i] = obj[i] || 0;
        return arr;
    }
    // Handle objects with numeric keys (dense)
    if (typeof obj === 'object' && obj !== null) {
        const numericKeys = Object.keys(obj).map(Number).filter(k => !isNaN(k) && k >= 0).sort((a, b) => a - b);
        if (numericKeys.length > 0 && numericKeys.every((k, i) => k === i)) {
            const arr = new Uint8Array(numericKeys.length);
            for (let i = 0; i < numericKeys.length; i++) arr[i] = obj[i] || 0;
            return arr;
        }
    }
    console.error(`Popup: Failed to convert field '${fieldName}' to Uint8Array. Received type: ${typeof obj}, value:`, obj);
    return new Uint8Array(0);
};


   /* const handleRegisterWebAuthn = async () => {
    clearMessages();
    if (isAppLocked) { // Check if the main application logic is locked
        setError("Please unlock with Master Passphrase first to manage Security Keys.");
        setWebAuthnStatus(''); 
        return;
    }
    setWebAuthnStatus('Starting Security Key registration...'); 
    setIsLoading(true);

    chrome.runtime.sendMessage({ action: "webAuthnStartRegistration" }, async (response) => {
        setIsLoading(false); // Stop initial loading once options are received or fail
        if (chrome.runtime.lastError || !response?.success || !response.optionsForCreate) {
            setError(`Registration start error: ${chrome.runtime.lastError?.message || response?.error || 'No options received'}`);
            setWebAuthnStatus(''); 
            return;
        }
        
        setWebAuthnStatus('Browser prompt for Security Key should appear...');
        try {
            const opts = response.optionsForCreate;
            // console.log("Popup [WA_REG]: Raw optionsForCreate from BG:", JSON.parse(JSON.stringify(opts)));

            const challengeProcessed = objectToUint8Array(opts.challenge, "reg_challenge_from_bg");
            const userIdProcessed = objectToUint8Array(opts.user.id, "reg_user.id_from_bg");

            if (challengeProcessed.length < 16) {
                throw new Error(`Reconstructed registration challenge is too short (${challengeProcessed.length} bytes).`);
            }
            if (userIdProcessed.length === 0 && opts.user?.id) {
                throw new Error("User ID for registration could not be reconstructed properly from background data.");
            }

            const createOptions = {
                ...opts,
                challenge: challengeProcessed,
                user: { ...opts.user, id: userIdProcessed },
            };
            // console.log("Popup [WA_REG]: Final options for navigator.credentials.create():", createOptions);

            setIsLoading(true); // Start loading for browser/authenticator interaction
            const credential = await navigator.credentials.create({ publicKey: createOptions });
            
            // Log what the popup is about to send to the background
            // console.log("Popup [WA_REG]: Credential object from navigator.credentials.create():", credential);
            if (credential && credential.rawId) {
                // console.log("Popup [WA_REG]: Sending credential.rawId (type, byteLength, constructor):", 
                    typeof credential.rawId, 
                    credential.rawId.byteLength,
                    credential.rawId.constructor.name
                );
            } else {
                console.error("Popup [WA_REG]: credential.rawId is missing or null BEFORE sending to background!");
                throw new Error("Browser returned credential without rawId.");
            }

            setWebAuthnStatus('Security Key responded. Completing registration with CryptoPass...');
            // setIsLoading(true) is already set

            chrome.runtime.sendMessage(
                { action: "webAuthnCompleteRegistration", data: { createdCredential: credential } }, 
                (completeResponse) => {
                    setIsLoading(false);
                    if (chrome.runtime.lastError || !completeResponse?.success) {
                        setError(`Registration completion error: ${chrome.runtime.lastError?.message || completeResponse?.error || 'Unknown error'}`);
                        setWebAuthnStatus('');
                    } else {
                        setWebAuthnStatus(completeResponse.message || 'WebAuthn key registered successfully!');
                        // Update UI to reflect WebAuthn is now an option
                        setUnlockMethod("webauthn"); 
                        // Optionally, call initializeAppStates() if you want a full refresh of prefs,
                        // but setUnlockMethod might be enough for immediate UI change.
                        // initializeAppStates(); // This would re-fetch preferences
                    }
                }
            );
        } catch (err) {
            console.error("Popup [WA_REG]: Error in navigator.credentials.create() or data reconstruction:", err);
            setError(`Security Key registration failed: ${err.message || err.name}`);
            setWebAuthnStatus(''); 
            setIsLoading(false);
        }
    });
};*/


  /*  const handleWebAuthnUnlockAttempt = async () => {
        clearMessages();
        setWebAuthnStatus("Requesting Security Key. Please look for a system prompt..."); setIsLoading(true);
        chrome.runtime.sendMessage({ action: "webAuthnStartAuthentication" }, async (response) => {
            if (chrome.runtime.lastError || !response || !response.success || !response.optionsForGet) {
                setError(`Unlock start error: ${chrome.runtime.lastError?.message || response?.error || 'No options'}`);
                setWebAuthnStatus('Failed to start. Try Master Passphrase?'); setIsLoading(false); return;
            }
            setWebAuthnStatus('Browser prompt for Security Key should appear...');
            try {
                const opts = response.optionsForGet;
                const authOptions = {
                    ...opts,
                    challenge: objectToUint8Array(opts.challenge, "auth_challenge"),
                    allowCredentials: opts.allowCredentials.map(cred => ({ ...cred, id: objectToUint8Array(cred.id, "auth_cred.id") })),
                };
                if (authOptions.challenge.length < 16) throw new Error("Reconstructed auth challenge too short.");

                const assertion = await navigator.credentials.get({ publicKey: authOptions });
                setWebAuthnStatus('Security Key responded. Verifying...');
                chrome.runtime.sendMessage( { action: "webAuthnCompleteAuthentication", data: { assertion: assertion } }, (authResponse) => {
                    setIsLoading(false);
                    if (chrome.runtime.lastError || !authResponse || !authResponse.success) {
                        setError(`Unlock verification failed: ${chrome.runtime.lastError?.message || authResponse?.error || 'Unknown'}`);
                        setWebAuthnStatus('Verification failed. Try Master Passphrase?'); setWebAuthnVerifiedThisSession(false);
                    } else {
                        setWebAuthnStatus(''); setStatusMessage("Security Key verified! Enter Master Passphrase.");
                        setWebAuthnVerifiedThisSession(true); setTimeout(() => masterPassphraseInputRef.current?.focus(), 50);
                    }
                });
            } catch (err) { setError(`Security Key interaction failed: ${err.message || err.name}`); setWebAuthnStatus('Auth failed/cancelled. Try MP?'); setIsLoading(false); setWebAuthnVerifiedThisSession(false); }
        });
    };*/

    const handleWebAuthnUnlockAttempt = async () => {
    clearMessages();
    setWebAuthnStatus("Requesting Security Key. Please look for a system prompt...");
    setIsLoading(true);
    chrome.runtime.sendMessage({ action: "webAuthnStartAuthentication" }, async (response) => {
        if (chrome.runtime.lastError || !response || !response.success || !response.optionsForGet) {
            setError(`Unlock start error: ${chrome.runtime.lastError?.message || response?.error || 'No options'}`);
            setWebAuthnStatus('Failed to start. Try Master Passphrase?'); setIsLoading(false); return;
        }
        setWebAuthnStatus('Browser prompt for Security Key should appear...');
       /* try {
            const opts = response.optionsForGet;
            // --- CRITICAL: Convert challenge and allowCredentials[].id to Uint8Array ---
            const challenge = typeof opts.challenge === "string"
                ? objectToUint8Array(opts.challenge, "auth_challenge")
                : opts.challenge;
            /*const allowCredentials = (opts.allowCredentials || []).map(cred => ({
                ...cred,
                id: typeof cred.id === "string"
                    ? objectToUint8Array(cred.id, "auth_cred.id")
                    : cred.id
            }));*
            const allowCredentials = (opts.allowCredentials || []).map(cred => {
    // Only convert if it's a string or a plain object, NOT if already ArrayBuffer/Uint8Array
    if (cred.id instanceof Uint8Array) return cred;
    if (cred.id instanceof ArrayBuffer) return { ...cred, id: new Uint8Array(cred.id) };
    if (typeof cred.id === "string") return { ...cred, id: objectToUint8Array(cred.id, "auth_cred.id") };
    // Handle array-like objects (rare, but for safety)
    if (typeof cred.id === "object" && cred.id !== null && typeof cred.id.length === "number") {
        return { ...cred, id: objectToUint8Array(cred.id, "auth_cred.id") };
    }
    // Fallback: log error and skip
    console.error("Popup: allowCredentials.id is not a valid buffer or string", cred.id);
    return cred;
});
            // console.log("Popup: allowCredentials[0].id type:", typeof allowCredentials[0].id, allowCredentials[0].id.constructor.name);
// console.log("Popup: allowCredentials[0].id instanceof ArrayBuffer:", allowCredentials[0].id instanceof ArrayBuffer);
// console.log("Popup: allowCredentials[0].id instanceof Uint8Array:", allowCredentials[0].id instanceof Uint8Array);
            const authOptions = {
                ...opts,
                challenge,
                allowCredentials,
            };
            if (authOptions.challenge.length < 16) throw new Error("Reconstructed auth challenge too short.");

            const assertion = await navigator.credentials.get({ publicKey: authOptions });
            // console.log("Popup: allowCredentials[0].id type:", typeof allowCredentials[0].id, allowCredentials[0].id.constructor.name);
// console.log("Popup: allowCredentials[0].id instanceof ArrayBuffer:", allowCredentials[0].id instanceof ArrayBuffer);
// console.log("Popup: allowCredentials[0].id instanceof Uint8Array:", allowCredentials[0].id instanceof Uint8Array);
// console.log("Popup: allowCredentials[0].id byteLength:", allowCredentials[0].id?.byteLength, "length:", allowCredentials[0].id?.length);
            setWebAuthnStatus('Security Key responded. Verifying...');*/
              try {
            const opts = response.optionsForGet;
            
            // --- CRITICAL: Convert challenge and allowCredentials[].id to Uint8Array ---
            const challenge = objectToUint8Array(opts.challenge, "auth_challenge");

            // Rebuild the allowCredentials array, converting the Base64URL string ID to a Uint8Array.
            const finalAllowCredentials = (opts.allowCredentials || []).map(cred => {
                // The `cred.id` received from the background is now a Base64URL string.
                if (typeof cred.id !== 'string' || cred.id.length === 0) {
                    console.error("Popup: Invalid or empty credential ID string received from background:", cred);
                    // Return an object with an empty buffer that we can filter out.
                    return { ...cred, id: new Uint8Array(0) };
                }
                return {
                    ...cred,
                    id: objectToUint8Array(cred.id, `auth_cred.id_${cred.id.slice(0, 10)}`)
                };
            }).filter(cred => cred.id.byteLength > 0); // Filter out any that failed conversion.

            // --- ADDED VALIDATION ---
            // This is a crucial final check before calling the browser API.
            if (finalAllowCredentials.length === 0 && opts.allowCredentials?.length > 0) {
                 throw new Error("Failed to process any credential IDs for authentication. Check console for errors.");
            }
            if (finalAllowCredentials.some(cred => !(cred.id instanceof Uint8Array))) {
                throw new Error("A processed credential ID is not a valid Uint8Array.");
            }
            // console.log("Popup [WA_AUTH]: Processed finalAllowCredentials to be used in navigator.get():", finalAllowCredentials);


            const authOptions = {
                ...opts,
                challenge: challenge,
                allowCredentials: finalAllowCredentials,
            };

            if (authOptions.challenge.length < 16) throw new Error("Reconstructed auth challenge too short.");
            if (authOptions.allowCredentials.length === 0) throw new Error("No valid WebAuthn credentials found to attempt authentication.");

            const assertion = await navigator.credentials.get({ publicKey: authOptions });

             const serializableAssertion = {
                id: assertion.id, // id is already a string
                rawId: bufferToBase64URL(assertion.rawId), // Convert ArrayBuffer to string
                type: assertion.type,
                response: {
                    clientDataJSON: bufferToBase64URL(assertion.response.clientDataJSON),
                    authenticatorData: bufferToBase64URL(assertion.response.authenticatorData),
                    signature: bufferToBase64URL(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToBase64URL(assertion.response.userHandle) : null,
                },
            };
            setWebAuthnStatus('Security Key responded. Verifying...');

            chrome.runtime.sendMessage(
                { action: "webAuthnCompleteAuthentication", data: { assertion: serializableAssertion } },
                (authResponse) => {
                    setIsLoading(false);
                    if (chrome.runtime.lastError || !authResponse || !authResponse.success) {
                        setError(`Unlock verification failed: ${chrome.runtime.lastError?.message || authResponse?.error || 'Unknown'}`);
                        setWebAuthnStatus('Verification failed. Try Master Passphrase?'); setWebAuthnVerifiedThisSession(false);
                    } else {
                        setWebAuthnStatus(''); setStatusMessage("Security Key verified! Enter Master Passphrase.");
                        setWebAuthnVerifiedThisSession(true); setTimeout(() => masterPassphraseInputRef.current?.focus(), 50);
                    }
                }
            );
        } catch (err) {
            setError(`Security Key interaction failed: ${err.message || err.name}`);
            setWebAuthnStatus('Auth failed/cancelled. Try MP?');
            setIsLoading(false);
            setWebAuthnVerifiedThisSession(false);
        }
    });
};

    
    

    const handlePrimaryUnlockOrGenerate = () => {
        clearMessages();
        if (isAppLocked) {
            if (unlockMethod === 'webauthn' && !webAuthnVerifiedThisSession) {
                handleWebAuthnUnlockAttempt(); return; // Auto-trigger WebAuthn if it's the method and not yet verified
            }
            if (!masterPassphrase) { setError("Master Passphrase is required."); masterPassphraseInputRef.current?.focus(); return; }
        }
       

        if (isAppLocked && !masterPassphrase) {
        setError("Master Passphrase is required.");
        masterPassphraseInputRef.current?.focus();
        return;
    }
        if (!domain) { setError("Domain is required."); return; }
        if (!otop) { setError("OTOP is required."); return; }

        setGeneratedPassword(''); setIsLoading(true);
        setStatusMessage(isAppLocked ? "Unlocking & Generating..." : "Generating password...");
        const defaultProfileOptions = { length: 18, includeLowercase: true, includeUppercase: true, includeNumbers: true, includeSymbols: true, requireEachCategory: true };
        chrome.runtime.sendMessage( { action: "generatePassword", data: { masterPassphrase, domain, username, otop, profileOptions: defaultProfileOptions } }, (response) => {
            setIsLoading(false);
            const duration = "..."; // Simplified
            if (chrome.runtime.lastError || !response || !response.password) {
                setError(`Operation failed: ${chrome.runtime.lastError?.message || response?.error || 'Unknown'}`);
                setStatusMessage(`Failed.`); if (isAppLocked) setWebAuthnVerifiedThisSession(false);
            } else {
                setGeneratedPassword(response.password); setStatusMessage(`Password generated.`);
                if (isAppLocked) { setIsAppLocked(false); /* setMasterPassphrase(''); // Optional */ }
            }
        });
    };

    const handleLock = () => {
        clearMessages(true); setIsLoading(true);
        chrome.runtime.sendMessage({ action: "lock" }, (response) => {
            setIsLoading(false); // Stop loading after lock attempt
            if (response && response.success) {
                initializeAppStates(); // Re-initialize to correctly set lock state and preferred unlock UI
            } else { setError("Failed to lock. " + (chrome.runtime.lastError?.message || '')); }
        });
    };

    const handleCopyToClipboard = () => {
        clearMessages();
        if (generatedPassword) {
            navigator.clipboard.writeText(generatedPassword)
                .then(() => setStatusMessage("Password copied!"))
                .catch(err => { console.error('Copy fail:', err); setError('Failed to copy.'); });
        }
    };

    const switchToMasterPassphraseUnlock = () => {
        clearMessages(); setUnlockMethod("master_passphrase");
        setWebAuthnVerifiedThisSession(false); setStatusMessage("Enter Master Passphrase.");
        setTimeout(() => masterPassphraseInputRef.current?.focus(), 0);
    };

    // --- Derived UI Control Variables ---
    const showWebAuthnAsPrimaryUnlock = isAppLocked && unlockMethod === 'webauthn' && !webAuthnVerifiedThisSession;
    const showMasterPassphraseInput = isAppLocked && (unlockMethod === 'master_passphrase' || (unlockMethod === 'webauthn' && webAuthnVerifiedThisSession));
    const showDataEntryAndGenerateButton = !isAppLocked || showMasterPassphraseInput; // Show if unlocked OR if MP input is ready
    //const mainButtonText = isAppLocked ? (showWebAuthnAsPrimaryUnlock ? 'Unlock with Security Key' : 'Unlock & Generate') : 'Generate Password';
    const mainButtonText = isAppLocked ? (unlockMethod === 'webauthn' && !webAuthnVerifiedThisSession ? 'Unlock with Security Key' : 'Unlock & Generate') : 'Generate Password';
    const showDataEntryFields = !isAppLocked || showMasterPassphraseInput;
     

    // --- Render ---
   /* if (unlockMethod === 'loading') {
        return <div style={{ padding: '20px', textAlign: 'center' }}>Loading CryptoPass...</div>;
    }

    return (
        <>
            <h3>CryptoPass</h3>
            {statusMessage && <p style={{ textAlign: 'center', fontSize: '0.9em', color: error || (webAuthnStatus && webAuthnStatus.toLowerCase().includes('fail')) ? 'red' : '#28a745', minHeight: '1.2em' }}>{statusMessage}</p>}
            {error && <p className="error-message" style={{ textAlign: 'center' }}>{error}</p>}
            {webAuthnStatus && !error && <p style={{ textAlign: 'center', fontSize: '0.9em', color: webAuthnStatus.toLowerCase().includes('fail') || webAuthnStatus.toLowerCase().includes('error') ? 'red' : 'inherit' }}>{webAuthnStatus}</p>}

            
            {isAppLocked && (
                <>
                    {unlockMethod === 'webauthn' && !webAuthnVerifiedThisSession && (
                        // This is the primary state for showing the WebAuthn unlock option
                        <div style={{ marginBottom: '10px' }}>
                            <button 
                                onClick={handleWebAuthnUnlockAttempt} 
                                disabled={isLoading} 
                                style={{width: '100%', marginBottom: '5px', backgroundColor: '#007bff', color: 'white'}}
                            >
                                {isLoading && webAuthnStatus.includes("Requesting") ? 'Requesting Key...' : 
                                 isLoading && webAuthnStatus.includes("Verifying") ? 'Verifying...' :
                                'Unlock with Security Key / Biometrics'}
                            </button>
                            <button 
                                onClick={switchToMasterPassphraseUnlock} 
                                disabled={isLoading} 
                                style={{fontSize: '0.8em', width: '100%', backgroundColor: '#6c757d', color: 'white'}}
                            >
                                Use Master Passphrase Instead
                            </button>
                        </div>
                    )}

                    {(unlockMethod === 'master_passphrase' || (unlockMethod === 'webauthn' && webAuthnVerifiedThisSession)) && (
                        // Show Master Passphrase input if it's the direct method OR if WebAuthn step is complete
                        <div className="form-group">
                            <label htmlFor="masterPassphrase">Master Passphrase:</label>
                            <input
                                ref={masterPassphraseInputRef}
                                type="password" id="masterPassphrase" value={masterPassphrase}
                                onChange={(e) => { setMasterPassphrase(e.target.value); clearMessages(); }}
                                disabled={isLoading}
                                autoFocus={true} // Always autofocus when this input is shown
                            />
                        </div>
                    )}
                </>
            )}

            {showDataEntryAndGenerateButton && (
                 <>
                    <div className="form-group">
                        <label htmlFor="domain">Domain:</label>
                        <input type="text" id="domain" value={domain}
                            onChange={(e) => { setDomain(e.target.value); clearMessages(); setSelectedUsername(''); setUsername('');}}
                            disabled={isLoading} />
                    </div>
                 </>
            )}

            {!isAppLocked && ( /* Username mappings only when fully unlocked 
                <>
                    <div className="form-group">
                        <label htmlFor="usernameSelect">Account:</label>
                        {currentDomainUsernames.length > 0 && (
                            <select id="usernameSelect" value={selectedUsername} onChange={handleUsernameSelectionChange} disabled={isLoading} style={{ marginBottom: '5px', width: '100%' }}>
                                <option value="">-- Select or type new --</option>
                                {currentDomainUsernames.map(u => (<option key={u} value={u}>{u}</option>))}
                            </select>
                        )}
                        <input type="text" id="username" placeholder={currentDomainUsernames.length > 0 ? "Selected or type new" : "Username (optional)"} value={username}
                            onChange={(e) => { setUsername(e.target.value); clearMessages(); if (currentDomainUsernames.includes(e.target.value)) setSelectedUsername(e.target.value); else setSelectedUsername(""); }}
                            disabled={isLoading} />
                        {username && domain && (
                            <button onClick={handleAddMapping} disabled={isLoading} style={{ fontSize: '0.8em', padding: '4px 8px', marginTop: '5px', backgroundColor: '#28a745', width: 'auto' }}>
                                Save Account
                            </button>
                        )}
                    </div>
                    {currentDomainUsernames.length > 0 && (
                        <div style={{ fontSize: '0.8em', marginBottom: '10px', border: '1px solid #eee', padding: '5px', borderRadius: '4px' }}>
                            <strong>Saved for {domain}:</strong>
                            <ul style={{ listStyle: 'none', paddingLeft: '0', margin: '5px 0 0 0', maxHeight: '60px', overflowY: 'auto' }}>
                                {currentDomainUsernames.map(u => (
                                    <li key={u} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '3px 0', borderBottom: '1px solid #f0f0f0' }}>
                                        <span onClick={() => { setSelectedUsername(u); setUsername(u); clearMessages(); }} style={{ cursor: 'pointer', flexGrow: 1 }}>{u}</span>
                                        <button onClick={() => handleRemoveMapping(u)} style={{ fontSize: '0.7em', padding: '2px 5px', backgroundColor: '#dc3545', border: 'none', color: 'white', borderRadius: '3px', cursor: 'pointer', marginLeft: '5px' }}>X</button>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}
                </>
            )}

             {showDataEntryAndGenerateButton && (
                <div className="form-group">
                    <label htmlFor="otop">OTOP:</label>
                    <input type="password" id="otop" value={otop} onChange={(e) => { setOtop(e.target.value); clearMessages(); }} disabled={isLoading} />
                </div>
             )}

            { (showWebAuthnAsPrimaryUnlock || showMasterPassphraseInput || !isAppLocked) && (
                <button
                    onClick={handlePrimaryUnlockOrGenerate}
                    disabled={isLoading || (showDataEntryAndGenerateButton && (!otop || !domain)) || (isAppLocked && showMasterPassphraseInput && !masterPassphrase) }
                    style={{width: '100%', marginBottom: '10px'}} >
                    {isLoading ? 'Processing...' : mainButtonText}
                </button>
            )}

            <div style={{marginTop: '15px', borderTop: '1px solid #eee', paddingTop: '10px'}}>
                {!isAppLocked && (
                    <button onClick={handleRegisterWebAuthn} disabled={isLoading} style={{backgroundColor: '#17a2b8', marginBottom: '5px', width: '100%'}}>
                        Manage Security Keys
                    </button>
                )}
                <button onClick={handleLock} disabled={isLoading} style={{ backgroundColor: isAppLocked? "#6c757d" : "#ffc107", color: isAppLocked? "white": "black", width: '100%' }}>
                    {isAppLocked ? "App is Locked" : "Lock Now"}
                </button>
            </div>

            {generatedPassword && !isAppLocked && (
                <div className="password-display" style={{marginTop: '15px'}}>
                    <p style={{margin: '0 0 5px 0'}}><strong>Generated:</strong></p>
                    <p style={{fontFamily: 'monospace', wordBreak: 'break-all', margin: '0 0 10px 0', backgroundColor: 'white', padding: '5px', borderRadius: '3px'}}>{generatedPassword}</p>
                    <button onClick={handleCopyToClipboard} style={{ fontSize: '0.9em', width: '100%' }}>Copy to Clipboard</button>
                </div>
            )}
        </>
    );
}*/


        if (unlockMethod === 'loading') {
        return <div style={{padding:'20px', textAlign:'center', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif'}}>Loading CryptoPass...</div>;
    }

    return (
        <>
            <h3>CryptoPass</h3>

            {/* --- Status Messages with transition classes --- */}
            <div className={`message-container message-status ${statusMessage && !error && !webAuthnStatus ? 'visible' : ''}`}>
                <p>{statusMessage}</p>
            </div>
            <div className={`message-container message-error ${error ? 'visible' : ''}`}>
                <p>{error}</p>
            </div>
            <div className={`message-container message-webauthn ${webAuthnStatus && !error ? 'visible' : ''} ${webAuthnStatus && webAuthnStatus.match(/fail|error|unknown/i) ? 'error' : ''}`}>
                <p>{webAuthnStatus}</p>
            </div>
            
            {/* --- Unlock Mechanism --- */}
            {isAppLocked && (
                <>
                    {unlockMethod === 'webauthn' && !webAuthnVerifiedThisSession && (
                        <div className="form-group visible" style={{gap: '8px'}}> {/* Always visible if this condition met */}
                            <button 
                                onClick={handleWebAuthnUnlockAttempt} 
                                disabled={isLoading} 
                                className="primary" // Main action in this state
                            >
                                {isLoading && webAuthnStatus.includes("Requesting") ? 'Requesting Key...' : 
                                 isLoading && webAuthnStatus.includes("Verifying") ? 'Verifying...' :
                                 isLoading && webAuthnStatus.includes("Browser") ? 'Waiting for Key...' : // Added for clarity
                                'Unlock with Security Key / Biometrics'}
                            </button>
                            <button 
                                onClick={switchToMasterPassphraseUnlock} 
                                disabled={isLoading} 
                                className="secondary" // Fallback action
                            >
                                Use Master Passphrase Instead
                            </button>
                        </div>
                    )}

                    {/* Master Passphrase Input Section */}
                    <div className={`form-group ${showMasterPassphraseInput ? 'visible' : 'hidden'}`}>
                        <label htmlFor="masterPassphrase">Master Passphrase:</label>
                        <input
                            ref={masterPassphraseInputRef}
                            type="password" id="masterPassphrase" value={masterPassphrase}
                            onChange={(e) => { setMasterPassphrase(e.target.value); clearMessages(); }}
                            disabled={isLoading}
                            autoFocus={showMasterPassphraseInput} // Autofocus when this input section is shown
                        />
                    </div>
                </>
            )}

            {/* --- Core Data Entry Fields (Domain, OTOP) --- */}
            {/* These are shown if app is unlocked, OR if it's locked but ready for MP entry */}
            <div className={`form-group ${showDataEntryFields ? 'visible' : 'hidden'}`}>
                <label htmlFor="domain">Domain:</label>
                <input type="text" id="domain" value={domain}
                    onChange={(e) => { setDomain(e.target.value); clearMessages(); setSelectedUsername(''); setUsername('');}}
                    disabled={isLoading} 
                />
            </div>
            
            {/* Username Mappings Section - Only when fully unlocked */}
            <div className={`form-group ${!isAppLocked ? 'visible' : 'hidden'}`}> {/* This whole section animates */}
                <label htmlFor="usernameSelect">Account:</label>
                {currentDomainUsernames.length > 0 && (
                    <select id="usernameSelect" value={selectedUsername} onChange={handleUsernameSelectionChange} disabled={isLoading} style={{marginBottom:'5px'}}>
                        <option value="">-- Select or type new --</option>
                        {currentDomainUsernames.map(u=>(<option key={u} value={u}>{u}</option>))}
                    </select>
                )}
                <input type="text" id="username" placeholder={currentDomainUsernames.length>0?"Selected or type new":"Username (optional)"} value={username}
                    onChange={(e)=>{setUsername(e.target.value);clearMessages();if(currentDomainUsernames.includes(e.target.value))setSelectedUsername(e.target.value);else setSelectedUsername("");}}
                    disabled={isLoading} />
                {username && domain && (
                    <button onClick={handleAddMapping} disabled={isLoading} className="tertiary success" style={{marginTop:'8px', width:'auto', padding:'6px 10px'}}>
                        Save Account
                    </button>
                )}
            </div>

            <div className={`accounts-list-container ${!isAppLocked && currentDomainUsernames.length > 0 ? 'visible' : ''}`}>
                <strong>Saved for {domain}:</strong>
                <ul>
                    {currentDomainUsernames.map(u=>(<li key={u}>
                        <span onClick={()=>{setSelectedUsername(u);setUsername(u);clearMessages();}}>{u}</span>
                        <button onClick={()=>handleRemoveMapping(u)} className="tertiary danger">X</button>
                    </li>))}
                </ul>
            </div>

            <div className={`form-group ${showDataEntryFields ? 'visible' : 'hidden'}`}>
                <label htmlFor="otop">OTOP:</label>
                <input type="password" id="otop" value={otop} onChange={(e)=>{setOtop(e.target.value);clearMessages();}} disabled={isLoading} />
            </div>


            {/* Main Action Button: Unlock & Generate / Generate Password */}
            {/* Show if MP input is ready OR if app is fully unlocked.
                OR if WebAuthn is primary and not yet verified (its specific button is handled above, this one handles the MP step after)
            */}
            { (showMasterPassphraseInput || !isAppLocked) && ( // Simpler condition for showing the MP unlock/generate button
                 <div className={`form-group ${showMasterPassphraseInput || !isAppLocked ? 'visible' : 'hidden'}`}>
                    <button
                        onClick={handlePrimaryUnlockOrGenerate}
                        disabled={isLoading || 
                                  (!isAppLocked && (!domain || !otop)) || // If unlocked, need domain/otop for "Generate"
                                  (isAppLocked && showMasterPassphraseInput && !masterPassphrase) // If MP input shown, MP needed for "Unlock & Generate"
                                 }
                        className="primary" 
                    >
                        {isLoading ? 'Processing...' : (isAppLocked && showMasterPassphraseInput ? 'Unlock & Generate Password' : 'Generate Password')}
                    </button>
                </div>
            )}


            {/* --- Footer Buttons --- */}
            <div style={{marginTop:'auto', borderTop:'1px solid #e0e0e0', paddingTop:'12px', display: 'flex', flexDirection: 'column', gap: '8px'}}>
                {!isAppLocked && (
                    <button onClick={handleRegisterWebAuthn} disabled={isLoading} className="secondary">
                        Manage Security Keys
                    </button>
                )}
                <button onClick={handleLock} disabled={isLoading} className={isAppLocked ? "tertiary" : "secondary"}>
                    {isAppLocked ? "App is Locked" : "Lock Now"}
                </button>
            </div>

            {/* Generated Password Display - only when available and app is unlocked */}
            <div className={`password-display ${generatedPassword && !isAppLocked ? 'visible' : ''}`}>
                <strong>Generated:</strong>
                <pre>{generatedPassword}</pre>
                <button onClick={handleCopyToClipboard} className="tertiary" style={{width:'100%', marginTop:'8px'}}>Copy to Clipboard</button>
            </div>
        </>
    );
}




export default App;