// Data Encryption Utilities
// Author: Alex Chen (Tech Lead)
// Issue: #20

import crypto from 'crypto';
import bcrypt from 'bcrypt';

// Encryption configuration
const ALGORITHM = 'aes-256-gcm';
const SALT_ROUNDS = 12;

export class Encryption {
  constructor() {
    this.key = Buffer.from(process.env.ENCRYPTION_KEY || crypto.randomBytes(32));
    if (!process.env.ENCRYPTION_KEY) {
      console.warn('⚠️  No ENCRYPTION_KEY found in environment, using random key');
    }
  }

  // Encrypt sensitive data
  encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  }

  // Decrypt sensitive data
  decrypt(encryptedData) {
    const { encrypted, iv, authTag } = encryptedData;

    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      this.key,
      Buffer.from(iv, 'hex')
    );

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  // Hash passwords
  async hashPassword(password) {
    return bcrypt.hash(password, SALT_ROUNDS);
  }

  // Verify passwords
  async verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  }

  // Generate secure random tokens
  generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Hash data (one-way)
  hashData(data) {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }
}

// Environment variable encryption
export const encryptEnvVar = (value) => {
  const encryption = new Encryption();
  const encrypted = encryption.encrypt(value);
  return JSON.stringify(encrypted);
};

export const decryptEnvVar = (encryptedValue) => {
  const encryption = new Encryption();
  const encrypted = JSON.parse(encryptedValue);
  return encryption.decrypt(encrypted);
};

// File encryption
export const encryptFile = async (filePath) => {
  const fs = require('fs').promises;
  const encryption = new Encryption();

  const data = await fs.readFile(filePath, 'utf8');
  const encrypted = encryption.encrypt(data);

  await fs.writeFile(`${filePath}.encrypted`, JSON.stringify(encrypted));
  return `${filePath}.encrypted`;
};

export const decryptFile = async (encryptedFilePath) => {
  const fs = require('fs').promises;
  const encryption = new Encryption();

  const encryptedData = await fs.readFile(encryptedFilePath, 'utf8');
  const encrypted = JSON.parse(encryptedData);
  const decrypted = encryption.decrypt(encrypted);

  const outputPath = encryptedFilePath.replace('.encrypted', '');
  await fs.writeFile(outputPath, decrypted);
  return outputPath;
};

export default new Encryption();