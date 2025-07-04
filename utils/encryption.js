import crypto from 'crypto';

const ALGORITHM = 'aes-256-cbc';
const KEY = crypto.createHash('sha256').update(process.env.ENCRYPTION_SECRET).digest();
const IV = Buffer.alloc(16, 0); // Static IV for simplicity

export function encrypt(text) {
  try {
    const cipher = crypto.createCipheriv(ALGORITHM, KEY, IV);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch {
    return null;
  }
}

export function decrypt(text) {
  try {
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, IV);
    let decrypted = decipher.update(text, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return null;
  }
}

export function generateRandomUsername() {
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  let username = '';
  for (let i = 0; i < 9; i++) {
    username += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return username;
}
