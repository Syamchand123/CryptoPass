// popup/App.js
import React, { useState, useEffect } from 'react';
// We don't have access to node:crypto or argon2 directly in browser popup JS
// We will use chrome.runtime.sendMessage to communicate with background.js

function App() {
    const [masterPassphrase, setMasterPassphrase] = useState('');
    const [domain, setDomain] = useState('');
    const [username, setUsername] = useState('');
    const [otop, setOtop] = useState('');
    const [generatedPassword, setGeneratedPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    // Get current domain when popup opens
    useEffect(() => {
        if (chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({ action: "getDomain" }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Error getting domain:", chrome.runtime.lastError.message);
                    setError("Could not get current domain. Is a tab active?");
                    return;
                }
                if (response && response.domain) {
                    setDomain(response.domain);
                } else if (response && response.error) {
                    console.warn("Background script error getting domain:", response.error);
                    // Don't show an error here, user might be on newtab page
                }
            });
        } else {
            // For development outside extension (e.g. `parcel popup/popup.html`)
            console.warn("chrome.runtime.sendMessage not available. Are you running in an extension context?");
            setDomain("dev.example.com"); // Placeholder for dev
        }
    }, []);

    const handleGeneratePassword = async () => {
        if (!masterPassphrase || !domain || !otop) {
            setError("Master Passphrase, Domain, and OTOP are required.");
            return;
        }
        setError('');
        setIsLoading(true);
        setGeneratedPassword('');

        // We'll use the CLI's logic via background script in a real extension
        // For now, let's mock the call to background.js
        if (chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage(
                {
                    action: "generatePassword", // This will trigger our background script
                    data: {
                        masterPassphrase, // Background will need this (securely handled later)
                        domain,
                        username,
                        otop
                    }
                },
                (response) => {
                    setIsLoading(false);
                    if (chrome.runtime.lastError) {
                        console.error("Error generating password:", chrome.runtime.lastError.message);
                        setError("Failed to generate password.");
                        return;
                    }
                    if (response && response.password) {
                        setGeneratedPassword(response.password);
                    } else {
                        setError("Received no password from background script.");
                    }
                }
            );
        } else {
            // Fallback for dev outside extension
            setTimeout(() => {
                setGeneratedPassword(`dev_pass_for_${domain}_${username}_${otop}`);
                setIsLoading(false);
            }, 500);
        }
    };

    const handleCopyToClipboard = () => {
        if (generatedPassword) {
            navigator.clipboard.writeText(generatedPassword)
                .then(() => {
                    // Maybe show a "Copied!" message briefly
                    console.log("Password copied to clipboard!");
                })
                .catch(err => {
                    console.error('Failed to copy password: ', err);
                    setError('Failed to copy password.');
                });
        }
    };


    return (
        <>
            <h3>CryptoPass</h3>
            <div className="form-group">
                <label htmlFor="masterPassphrase">Master Passphrase:</label>
                <input
                    type="password"
                    id="masterPassphrase"
                    value={masterPassphrase}
                    onChange={(e) => setMasterPassphrase(e.target.value)}
                    disabled={isLoading}
                />
            </div>
            <div className="form-group">
                <label htmlFor="domain">Domain:</label>
                <input
                    type="text"
                    id="domain"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    disabled={isLoading}
                />
            </div>
            <div className="form-group">
                <label htmlFor="username">Username (optional):</label>
                <input
                    type="text"
                    id="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    disabled={isLoading}
                />
            </div>
            <div className="form-group">
                <label htmlFor="otop">OTOP:</label>
                <input
                    type="password" // Keep OTOP somewhat hidden
                    id="otop"
                    value={otop}
                    onChange={(e) => setOtop(e.target.value)}
                    disabled={isLoading}
                />
            </div>
            <button onClick={handleGeneratePassword} disabled={isLoading}>
                {isLoading ? 'Generating...' : 'Generate Password'}
            </button>
            {error && <p className="error-message">{error}</p>}
            {generatedPassword && (
                <div className="password-display">
                    <p><strong>Generated:</strong> {generatedPassword}</p>
                    <button onClick={handleCopyToClipboard} style={{marginTop: "5px", fontSize: "0.9em"}}>
                        Copy to Clipboard
                    </button>
                </div>
            )}
        </>
    );
}

export default App;