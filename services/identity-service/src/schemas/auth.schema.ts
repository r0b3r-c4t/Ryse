
import { z } from 'zod';

// Correo normalizado para registro e inicio de sesión.
export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .pipe(z.email('El correo electrónico no es válido.'));

// Nombre de usuario normalizado.
export const usernameSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3, 'El nombre de usuario debe tener al menos 3 caracteres.')
  .max(30, 'El nombre de usuario no puede superar los 30 caracteres.')
  .regex(
    /^[a-z0-9_]+$/,
    'El nombre de usuario solo puede contener letras, números y guiones bajos.',
  );

// Política de contraseñas para el registro.
export const passwordSchema = z
  .string()
  .min(8, 'La contraseña debe tener al menos 8 caracteres.')
  .max(128, 'La contraseña no puede superar los 128 caracteres.');

// Esquema del cuerpo de registro.
export const registerSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  username: usernameSchema,
  email: emailSchema,
  password: passwordSchema,
});

// Esquema del cuerpo de inicio de sesión.
// No exigimos aquí la longitud mínima del registro para
// permitir autenticar cuentas existentes con contraseñas antiguas.
export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(128),
});

// Respuesta pública del registro.
export const registerResponseSchema = z.object({
  message: z.string(),
  user: z.object({
    id: z.string(),
    name: z.string().nullable(),
    username: z
      .string()
      .min(3)
      .max(30)
      .regex(/^[a-z0-9_]+$/),
    email: z.email(),
    createdAt: z.date(),
  }),
});

// Respuesta pública del inicio de sesión.
export const loginResponseSchema = z.object({
  message: z.string(),
  accessToken: z.string(),
  tokenType: z.literal('Bearer'),
  expiresIn: z.number().int(),
  user: z.object({
    id: z.string(),
    name: z.string().nullable(),
    email: z.email(),
  }),
});
