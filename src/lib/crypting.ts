import * as crypto from 'node:crypto';
import { SALT_LENGTH, ITERATIONS, KEY_LENGTH, DIGEST } from './constants';

export function getCrypt(str: string): string {
  if (!SALT_LENGTH || !ITERATIONS || !KEY_LENGTH) {
    throw new Error('Missing crucial environement variables');
  }

  const salt = crypto.randomBytes(SALT_LENGTH).toString('hex');
  const hash = crypto
    .pbkdf2Sync(str, salt, ITERATIONS, KEY_LENGTH, DIGEST)
    .toString('hex');
  return `${salt}:${hash}`;
}

export function getDecrypt(str: string, storedHash: string): boolean {
  if (!ITERATIONS || !KEY_LENGTH) {
    throw new Error('Missing crucial environement variables');
  }

  const [salt, originalHash] = storedHash.split(':');
  const hashToCompare = crypto
    .pbkdf2Sync(str, salt, ITERATIONS, KEY_LENGTH, DIGEST)
    .toString('hex');
  return crypto.timingSafeEqual(
    Buffer.from(originalHash),
    Buffer.from(hashToCompare),
  );
}
