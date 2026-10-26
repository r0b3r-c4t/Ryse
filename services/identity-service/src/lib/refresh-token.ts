import { createHash, randomBytes } from 'node:crypto';

/**
 * Genera un refresh token criptográficamente seguro.
 */
export const generateRefreshToken = (): string => {
    return randomBytes(32).toString('base64url');
};

/**
 * Genera el hash SHA-256 para almacenar el token
 * de forma segura en la base de datos.
 */
export const hashRefreshToken = (token: string): string => {
    return createHash('sha256')
        .update(token)
        .digest('hex');
};
