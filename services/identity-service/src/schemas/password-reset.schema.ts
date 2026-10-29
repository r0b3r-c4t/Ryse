import { z } from 'zod';

import { emailSchema, passwordSchema } from './auth.schema.js';

// Solicitar recuperación usando un correo electrónico.
export const requestPasswordResetSchema = z.object({
  email: emailSchema,
});

// Confirmar la recuperación mediante un token de un solo uso.
export const confirmPasswordResetSchema = z.object({
  token: z.string().min(1).max(512),
  password: passwordSchema,
});

// Respuesta pública genérica para la solicitud de recuperación.
export const passwordResetResponseSchema = z.object({
  message: z.string(),
});

// Respuesta para una recuperación confirmada.
export const passwordResetConfirmationResponseSchema = z.object({
  message: z.string(),
});
