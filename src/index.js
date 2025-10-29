//**************************************  Imports  **************************************//

// Kryptofunktionen einbinden
const CryptoAPI = document.createElement("script");
CryptoAPI.src = "./src/crypto.js";
document.body.appendChild(CryptoAPI);

//***************************************** Gamingzone **********************************************//

//**************************************  UI and Interaction  **************************************//

const output = document.getElementById("output");

// Hilfsfunktion um Console und Output zu bedienen
function log(...args) {
  console.log(...args);
  output.textContent += args.join(" ") + "\n";
}

userInput = {};

// Event listener für "Run" button
document.getElementById("runBtn").addEventListener("click", () => {
  output.textContent = ""; // Vor jedem Lauf resetten, sonst Layout kaputt.

  // Eingaben einlesen
  userInput.value = document.getElementById("plaintext").value;
  log("Original:", userInput.value);
  const plainkey = document.getElementById("plainkey").value;
  log("Passwort:", plainkey);

  // --- Hauptprogramm ---

  // Objekt "userInput" verschlüsseln -> "chiffrat"
  const chiffrat = encrypt(userInput, plainkey);

  // Format: Ausgabe in Hex mit führenden Nullen; Accent grave ausprobiert.
  log(
    `Encrypted Blocks ${chiffrat.length}:`,
    chiffrat.map((x) => "0x" + x.toString(16).padStart(16, "0"))
  );

  // "chiffrat" wieder entschlüsseln -> "result"
  const result = decrypt(chiffrat, plainkey);
  log("Decrypted:", result.value);
});
