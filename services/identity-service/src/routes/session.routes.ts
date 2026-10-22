
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';
import argon2 from 'argon2';
import { z } from 'zod';

import { prisma } from '../lib/prisma.js';

const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .toLowerCase()
    .max(254)
    .pipe(z.email('El correo electrónico no es válido.')),
  password: z.string().min(1).max(128),
});

const loginResponseSchema = z.object({
  message: z.string().meta({ example: 'Inicio de sesión exitoso.' }),
  accessToken: z.string().meta({ description: 'Token JWT de acceso.' }),
  tokenType: z.string().meta({ example: 'Bearer' }),
  expiresIn: z.number().int().meta({
    example: 900,
    description: 'Duración del token en segundos.',
  }),
  user: z.object({
    id: z.string().meta({ example: 'clx1234567890' }),
    name: z.string().nullable().meta({ example: 'Persona' }),
    email: z.email().meta({ example: 'persona@example.com' }),
  }),
});

const errorResponseSchema = z.object({
  error: z.string(),
  message: z.string(),
});

export const sessionRoutes = async (
  app: FastifyInstance,
): Promise<void> => {
  app.withTypeProvider<ZodTypeProvider>().post(
    '/auth/login',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Iniciar sesión',
        description:
          'Valida las credenciales y devuelve un token de acceso JWT válido por 15 minutos.',
        body: loginSchema,
        response: {
          200: loginResponseSchema.meta({
            description: 'Las credenciales son válidas.',
          }),
          400: errorResponseSchema.meta({
            description:
              'El cuerpo de la solicitud no cumple con los requisitos.',
          }),
          401: errorResponseSchema.meta({
            description: 'El correo o la contraseña son incorrectos.',
          }),
          500: errorResponseSchema.meta({
            description: 'Ocurrió un error inesperado al iniciar sesión.',
          }),
        },
      },
    },
    async (request, reply) => {
      const { email, password } = request.body;

      try {
        const user = await prisma.user.findUnique({
          where: { email },
        });

        if (!user) {
          return reply.code(401).send({
            error: 'INVALID_CREDENTIALS',
            message: 'Correo electrónico o contraseña incorrectos.',
          });
        }

        const passwordMatches = await argon2.verify(
          user.passwordHash,
          password,
        );

        if (!passwordMatches) {
          return reply.code(401).send({
            error: 'INVALID_CREDENTIALS',
            message: 'Correo electrónico o contraseña incorrectos.',
          });
        }

        const session = await prisma.session.create({
          data: {
            userId: user.id,
            expiresAt: new Date(Date.now() + 15 * 60 * 1000),
          },
        });

        const token = app.jwt.sign(
          {
            sub: user.id,
            email: user.email,
            sid: session.id,
          },
          {
            expiresIn: '15m',
          },
        );

        return reply.code(200).send({
          message: 'Inicio de sesión exitoso.',
          accessToken: token,
          tokenType: 'Bearer',
          expiresIn: 900,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
          },
        });
      } catch (error) {
        request.log.error({ err: error }, 'Failed to log in user');

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Ocurrió un error al iniciar sesión.',
        });
      }
    },
  );
};
