import { createHash, randomBytes } from 'node:crypto';
import argon2 from 'argon2';

const PASSWORD_HASH_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

/**
 * Genera un token criptográficamente seguro de 256 bits.
 */
export const generateSecureToken = (): string => {
  return randomBytes(32).toString('base64url');
};

/**
 * Calcula el hash SHA-256 de un token para almacenarlo
 * de forma segura en la base de datos.
 */
export const hashToken = (token: string): string => {
  return createHash('sha256')
    .update(token)
    .digest('hex');
};

export const hashPassword = (password: string): Promise<string> => {
  return argon2.hash(password, PASSWORD_HASH_OPTIONS);
};

export const verifyPassword = (
  passwordHash: string,
  password: string,
): Promise<boolean> => {
  return argon2.verify(passwordHash, password);
};
