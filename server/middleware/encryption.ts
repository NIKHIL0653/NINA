import CryptoJS from 'crypto-js';

// Encryption configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'fallback-encryption-key-32-chars';
const ALGORITHM = 'AES';

// Ensure key is 32 bytes (256 bits)
function normalizeKey(key: string): string {
  // If key is shorter than 32 bytes, pad it
  if (key.length < 32) {
    return key.padEnd(32, '0');
  }
  // If key is longer than 32 bytes, truncate it
  return key.substring(0, 32);
}

// Encrypt data
export function encryptData(data: string): string {
  try {
    const key = normalizeKey(ENCRYPTION_KEY);
    const encrypted = CryptoJS.AES.encrypt(data, key).toString();
    return encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt data');
  }
}

// Decrypt data
export function decryptData(encryptedData: string): string {
  try {
    const key = normalizeKey(ENCRYPTION_KEY);
    const bytes = CryptoJS.AES.decrypt(encryptedData, key);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);

    if (!decrypted) {
      throw new Error('Decryption failed - invalid data or key');
    }

    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt data');
  }
}

// Encrypt object (converts to JSON string first)
export function encryptObject(data: any): string {
  const jsonString = JSON.stringify(data);
  return encryptData(jsonString);
}

// Decrypt object (parses from JSON string)
export function decryptObject<T = any>(encryptedData: string): T {
  const jsonString = decryptData(encryptedData);
  return JSON.parse(jsonString);
}

// Generate hash for data integrity
export function generateHash(data: string): string {
  return CryptoJS.SHA256(data).toString();
}

// Verify data integrity
export function verifyIntegrity(data: string, hash: string): boolean {
  const computedHash = generateHash(data);
  return computedHash === hash;
}

// Encrypt PHI data before storage
export function encryptPHI(data: any): { encrypted: string; hash: string } {
  const dataString = JSON.stringify(data);
  const encrypted = encryptData(dataString);
  const hash = generateHash(dataString);

  return { encrypted, hash };
}

// Decrypt PHI data with integrity check
export function decryptPHI<T = any>(encrypted: string, hash: string): T {
  const decryptedString = decryptData(encrypted);

  // Verify integrity
  if (!verifyIntegrity(decryptedString, hash)) {
    throw new Error('Data integrity check failed - data may have been tampered with');
  }

  return JSON.parse(decryptedString);
}

// Field-level encryption for specific PHI fields
export const PHI_FIELDS = [
  'ssn',
  'medical_record_number',
  'insurance_id',
  'credit_card',
  'bank_account',
  'diagnosis_details',
  'treatment_notes',
  'medication_history',
  'allergy_details',
  'emergency_contact_phone',
  'emergency_contact_email'
];

// Encrypt specific fields in an object
export function encryptPHIFields(data: any): any {
  const encrypted = { ...data };

  for (const field of PHI_FIELDS) {
    if (encrypted[field]) {
      encrypted[field] = encryptData(String(encrypted[field]));
    }
  }

  return encrypted;
}

// Decrypt specific fields in an object
export function decryptPHIFields(data: any): any {
  const decrypted = { ...data };

  for (const field of PHI_FIELDS) {
    if (decrypted[field]) {
      try {
        decrypted[field] = decryptData(String(decrypted[field]));
      } catch (error) {
        console.warn(`Failed to decrypt field ${field}:`, error);
        // Keep encrypted value if decryption fails
      }
    }
  }

  return decrypted;
}

// Secure key derivation (for future use with user-specific keys)
export function deriveKey(password: string, salt: string): string {
  return CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 10000
  }).toString();
}

// Generate secure random salt
export function generateSalt(): string {
  return CryptoJS.lib.WordArray.random(128 / 8).toString();
}

// Encrypt file data (for medical documents)
export function encryptFile(buffer: Buffer): string {
  const base64Data = buffer.toString('base64');
  return encryptData(base64Data);
}

// Decrypt file data
export function decryptFile(encryptedData: string): Buffer {
  const base64Data = decryptData(encryptedData);
  return Buffer.from(base64Data, 'base64');
}

// Database field encryption/decryption middleware
export class DatabaseEncryption {
  // Encrypt data before saving to database
  static encryptForStorage(data: any): any {
    if (typeof data === 'object' && data !== null) {
      return encryptPHIFields(data);
    }
    return data;
  }

  // Decrypt data after retrieving from database
  static decryptFromStorage(data: any): any {
    if (typeof data === 'object' && data !== null) {
      return decryptPHIFields(data);
    }
    return data;
  }
}

// API response encryption for sensitive endpoints
export function encryptAPIResponse(data: any): { encrypted: string; key: string } {
  // Generate a one-time key for this response
  const responseKey = require('crypto').randomBytes(32).toString('hex');
  const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), responseKey).toString();

  return { encrypted, key: responseKey };
}

// Decrypt API response
export function decryptAPIResponse(encrypted: string, key: string): any {
  const bytes = CryptoJS.AES.decrypt(encrypted, key);
  const decrypted = bytes.toString(CryptoJS.enc.Utf8);
  return JSON.parse(decrypted);
}