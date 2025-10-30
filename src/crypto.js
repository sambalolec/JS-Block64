//**************************************  Imports  **************************************//

// Globale Konstanten laden
const GlobalConst = document.createElement("script");
GlobalConst.src = "./src/constants.js";
document.body.appendChild(GlobalConst);

//**************************************  Utilities  **************************************//

// ROL und ROR, in JS schmerzlich vermisst
function rol32(value, shift) {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}
function ror32(value, shift) {
  return ((value >>> shift) | (value << (32 - shift))) >>> 0;
}

// 64-Bit Zufallszahl; Für Analyse von s_Box unbedingt 0n zurück geben! Sonst Ergebnis unsinnig.
const randomBigInt = () => {
  const arr = new Uint32Array(2);
  crypto.getRandomValues(arr);
  let rand = 0n;
  for (const word of arr) {
    rand = (rand << 32n) + BigInt(word);
  }
  return rand;
};

//**************************************  Converter Functions  **************************************//

function objectTo64BitBlocks(obj) {
  // Objekt in Bytes umwandeln (JSON + UTF-8)
  const encoder = new TextEncoder();
  const bytes = encoder.encode(JSON.stringify(obj));

  // Uint8Array in 64-Bit Blöcke aufteilen, padden und in BigInt umwandeln
  const blockCount = (bytes.length + 7) >> 3; // schnelles Aufrunden auf nächstes Vielfaches von 8 (Assemblertrick)
  const blocks = new Array(blockCount);
  for (let i = 0; i < blockCount; i++) {
    let block = 0n;
    // 8 Bytes pro Block
    for (let j = 0; j < 8; j++) {
      const byte = bytes[i * 8 + j] ?? 0; // Padding mit 0, falls Block unvollständig
      block |= BigInt(byte) << BigInt(8 * j); // Bytes in BigInt verschieben
    }
    blocks[i] = block;
  }
  return blocks;
}

function blocks64BitToObj(blocks) {
  const bytes = [];

  // 64-Bit Blöcke zurück in Bytes umwandeln
  for (const block of blocks) {
    // 8 Bytes pro Block (Little-Endian)
    for (let i = 0; i < 8; i++) {
      const byte = Number((block >> BigInt(8 * i)) & 0xffn);
      bytes.push(byte);
    }
  }

  // Eventuelle Padding-Nullbytes entfernen
  while (bytes.length && bytes[bytes.length - 1] === 0) {
    bytes.pop();
  }

  // Bytes zurück zu String
  const decoder = new TextDecoder(); // UTF-8
  return JSON.parse(decoder.decode(new Uint8Array(bytes)));
}

//**************************************  Core Functions  **************************************//

function s_Box(uint32) {
  // Berechnet eine binäre Prüfsumme im Bereich b00000-b10111 (0-23)
  const hash = (n = uint32) => {
    let x = Math.imul(n, 0x9e3779b1) >>> 0;
    x ^= x << 5;
    x = x >>> 5;
    x *= 24;
    return x >>> 27;
  };

  // Mit dem Hash das Alphabet festlegen
  // Für Tests und Analyse auf feste Werte zwischen 0-23 setzen!
  const sboxes = ALPHABETS[hash()];

  // 32 Bit Input in 4 Blöcke zu je 8 Bit zerlegen
  const bytes = [
    uint32 & 0xff,
    (uint32 >>> 8) & 0xff,
    (uint32 >>> 16) & 0xff,
    (uint32 >>> 24) & 0xff,
  ];

  // Nichtlineare Substitution durch die Werte in den dicken S-Boxen
  const [v0, v1, v2, v3] = bytes.map((byte, i) => sboxes[i][byte] & 0xff);

  // Die Bytes wieder zu einer 32-Bit Zahl kombinieren und mixen
  const rol = 10; // Experimentell
  const ror = 11; // Experimentell
  const tmp = (v0 | (v1 << 8) | (v2 << 16) | (v3 << 24)) >>> 0;
  const merged = (tmp + rol32(tmp, rol) + ror32(tmp, ror)) >>> 0;
  return merged;
}

function feistel(block, key = 0n) {
  const rounds = 5; // Experimentell

  const data = block ^ key;

  // 64-Bit BigInt in linke und rechte Hälfte zerlegen
  let left = Number(data & MASK32) >>> 0;
  let right = Number((data >> 32n) & MASK32) >>> 0;

  // Rock´n roll
  for (let r = 0; r < rounds; r++) {
    const newLeft = right;
    const newRight = left ^ s_Box(right);
    left = newLeft;
    right = newRight;
  }

  // Die beiden Hälften rekombinieren
  let out = BigInt(right) & MASK32;
  out |= (BigInt(left) & MASK32) << 32n;

  // Erneut mit Blockkey verXodern und zurück geben
  return out ^ key;
}

//**************************************  Keymanagement  **************************************//

class Key {
  #seed0 = 0n;
  #seed1 = 0n;

  // aus dem Passwort zwei 64 Bit Seeds erzeugen,
  // ... die mathematisch praktisch nix miteinander zu tun haben sollten
  init(passphrase) {
    // Mit krummen Werten initialisieren
    this.#seed0 = SQRT2;
    this.#seed1 = SQRT3;

    // Passwort in Blöcke zu je 64 Bit konvertieren,
    // ... auf mindestens 3 Blöcke (192 Bit) verlängern und verschmieren
    let passBlocks = objectTo64BitBlocks(passphrase);
    passBlocks.push(LOGNAT, LN2);
    passBlocks[0] = (passBlocks[0] * KNUTH) & MASK64;
    passBlocks[1] = (passBlocks[1] * (passBlocks[0] | 1n)) & MASK64;
    passBlocks[2] = (passBlocks[2] * (passBlocks[1] | 1n)) & MASK64;

    // Alle Blöcke miteinander vermischen
    let feedback = PI;
    const passCrypt = (blocks) => {
      blocks.forEach((block, i) => {
        blocks[i] = feistel((block + feedback) & MASK64, this.newValue);
        feedback = blocks[i];
      });
      return blocks;
    };

    // Initiale Seeds für den XorShift erzeugen
    for (let i = 0; i < 3; i++) {
      passCrypt(passBlocks);
      this.#seed0 ^= passBlocks[passBlocks.length - 1];
      passCrypt(passBlocks);
      this.#seed1 ^= passBlocks[passBlocks.length - 1];
    }
  }

  // Bei jedem Aufruf einen frischen Key generieren mit XorShift128+
  get newValue() {
    let s0 = this.#seed0;
    const s1 = this.#seed1;
    this.#seed0 = s1;
    s0 ^= s0 << 23n;
    s0 ^= s0 >> 17n;
    s0 ^= s1;
    s0 ^= s1 >> 26n;
    this.#seed1 = s0;
    return (this.#seed1 + this.#seed0) & MASK64;
  }
}

//**************************************  API  **************************************//

function encrypt(data, passphrase) {
  const SessionKey = new Key();

  // Input in Binary umwandeln und in Random-Blocks kapseln
  const blocks = objectTo64BitBlocks(data);
  blocks.unshift(randomBigInt());
  blocks.push(randomBigInt());

  // Aufwärts verschlüsseln mit CBC
  SessionKey.init(passphrase + "up");
  let feedback = SQRT5;
  for (let i = 0; i < blocks.length; i++) {
    blocks[i] ^= feedback;
    blocks[i] = feistel(blocks[i], SessionKey.newValue);
    feedback = blocks[i];
  }

  // Rückwärts verschlüsseln mit CBC
  SessionKey.init(passphrase + "down");
  feedback = SQRT5;
  for (let i = blocks.length - 1; i >= 0; i--) {
    blocks[i] ^= feedback;
    blocks[i] = feistel(blocks[i], SessionKey.newValue);
    feedback = blocks[i];
  }

  return blocks;
}

function decrypt(blocks, passphrase) {
  const SessionKey = new Key();

  // Rückwärts entschlüsseln mit CBC
  SessionKey.init(passphrase + "down");
  let delayed = 0n;
  let feedback = SQRT5;
  for (let i = blocks.length - 1; i >= 0; i--) {
    delayed = blocks[i];
    blocks[i] = feistel(blocks[i], SessionKey.newValue);
    blocks[i] ^= feedback;
    feedback = delayed;
  }

  // Vorwärts entschlüsseln mit CBC
  SessionKey.init(passphrase + "up");
  feedback = SQRT5;
  for (let i = 0; i < blocks.length; i++) {
    delayed = blocks[i];
    blocks[i] = feistel(blocks[i], SessionKey.newValue);
    blocks[i] ^= feedback;
    feedback = delayed;
  }

  // Random-Blocks wieder entfernen
  blocks.shift();
  blocks.pop();
  // Binary zurückkonvertieren und ausgeben
  return blocks64BitToObj(blocks);
}

//************************************************************************************** */

/* 
Bugfix: Hash war fehlerhaft berechnet.
Routine jetzt überarbeitet, verbessert und in "s_Box" integriert.
Hashwerte jetzt gleichverteilt.

Lesbarkeit stellenweise verbessert, Kleinigkeiten.

Fehlt noch:
- Datenkompression; JSON.stringify bläst die Datenstruktur ungemein auf
*/
g;
