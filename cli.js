// cli.js
const readline = require('node:readline/promises'); // For reading user input
const { stdin: input, stdout: output } = require('node:process');
const { deriveMasterKey, generatePassword } = require('./passwordGenerator');

// Create an interface for reading input from the console
const rl = readline.createInterface({ input, output });

async function runCli() {
    console.log("CryptoPass CLI Password Generator\n");

    try {
        const masterPassphrase = await rl.question('Enter your Master Passphrase: ');
        if (!masterPassphrase) {
            console.error("Master passphrase cannot be empty.");
            return;
        }

        const domain = await rl.question('Enter the Domain (e.g., google.com): ');
        if (!domain) {
            console.error("Domain cannot be empty.");
            return;
        }

        const username = await rl.question('Enter your Username for this domain: ');
        // Username can sometimes be empty, depending on the service, so we don't strictly check

        const otop = await rl.question('Enter your OTOP (One-Time Cryptographic Password): ');
        if (!otop) {
            console.error("OTOP cannot be empty.");
            return;
        }

        console.log("\nDeriving master key (this may take a moment)...");
        const masterKeyBinary = await deriveMasterKey(masterPassphrase);
        // In a real app, you wouldn't log the master key, even in hex.
        // console.log("Master Key derived (hex):", masterKeyBinary.toString('hex'));

        console.log("Generating password...");
        const password = generatePassword(masterKeyBinary, domain, username, otop);

        console.log("\n------------------------------------");
        console.log("Generated Password:", password);
        console.log("------------------------------------\n");
        console.log("IMPORTANT: This is a prototype. Do not use for real passwords yet.");

    } catch (error) {
        console.error("\nAn error occurred:", error.message);
    } finally {
        rl.close(); // Close the readline interface
    }
}

runCli();