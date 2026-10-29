import { z } from 'zod';

import { passwordSchema } from './auth.schema.js';

// Cambiar la contraseña desde una sesión autenticada.
export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(128),
    newPassword: passwordSchema,
  })
  .refine((data) => data.currentPassword !== data.newPassword, {
    message: 'La nueva contraseña debe ser diferente de la actual.',
    path: ['newPassword'],
  });

// Respuesta para el cambio de contraseña autenticado.
export const changePasswordResponseSchema = z.object({
  message: z.string(),
});
