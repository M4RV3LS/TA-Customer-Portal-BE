
const crypto = require('crypto');

// Generate a 256-bit (32-byte) API key and convert it to a hexadecimal string
// This will result in a 64-character hex string.
const apiKey = crypto.randomBytes(32).toString('hex');

// Generate a 384-bit (48-byte) JWT secret and convert it to a base64 string
// Base64 encoding is more compact than hex for binary data.
// 48 bytes will result in a string of approximately (48 * 4 / 3) = 64 base64 characters.
const jwtSecret = crypto.randomBytes(48).toString('base64');

console.log("API Key:", apiKey);
console.log("JWT Secret:", jwtSecret);