import type { FastifyInstance } from 'fastify';
import argon2 from 'argon2';
import { z } from 'zod';

import { prisma } from '../lib/prisma.js';

const loginSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(128),
});

export const sessionRoutes = async (app: FastifyInstance): Promise<void> => {
  app.post(
    '/auth/login',
    {
      attachValidation: true,
      schema: {
        tags: ['Authentication'],
        summary: 'Iniciar sesión',
        description:
          'Valida las credenciales y devuelve un token de acceso JWT válido por 15 minutos.',
        body: {
          type: 'object',
          properties: {
            email: {
              type: 'string',
              format: 'email',
              maxLength: 254,
            },
            password: {
              type: 'string',
              minLength: 1,
              maxLength: 128,
            },
          },
          required: ['email', 'password'],
        },
        response: {
          200: {
            description: 'Las credenciales son válidas.',
            type: 'object',
            properties: {
              message: { type: 'string', example: 'Inicio de sesión exitoso.' },
              accessToken: { type: 'string', description: 'Token JWT de acceso.' },
              tokenType: { type: 'string', example: 'Bearer' },
              expiresIn: {
                type: 'integer',
                example: 900,
                description: 'Duración del token en segundos.',
              },
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string', example: 'clx1234567890' },
                  name: { type: 'string', nullable: true, example: 'Persona' },
                  email: { type: 'string', format: 'email', example: 'persona@example.com' },
                },
                required: ['id', 'name', 'email'],
              },
            },
            required: ['message', 'accessToken', 'tokenType', 'expiresIn', 'user'],
          },
          400: {
            description: 'El cuerpo de la solicitud no cumple con los requisitos.',
            type: 'object',
            properties: {
              error: { type: 'string', example: 'VALIDATION_ERROR' },
              message: { type: 'string' },
            },
            required: ['error', 'message'],
          },
          401: {
            description: 'El correo o la contraseña son incorrectos.',
            type: 'object',
            properties: {
              error: { type: 'string', example: 'INVALID_CREDENTIALS' },
              message: { type: 'string' },
            },
            required: ['error', 'message'],
          },
          500: {
            description: 'Ocurrió un error inesperado al iniciar sesión.',
            type: 'object',
            properties: {
              error: { type: 'string', example: 'INTERNAL_SERVER_ERROR' },
              message: { type: 'string' },
            },
            required: ['error', 'message'],
          },
        },
      },
    },
    async (request, reply) => {
      const validation = loginSchema.safeParse(request.body);

      if (!validation.success) {
        return reply.code(400).send({
          error: 'VALIDATION_ERROR',
          message: 'Los datos proporcionados no son válidos.',
        });
      }

      const email = validation.data.email.toLowerCase();
      const { password } = validation.data;

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

        const passwordMatches = await argon2.verify(user.passwordHash, password);

        if (!passwordMatches) {
          return reply.code(401).send({
            error: 'INVALID_CREDENTIALS',
            message: 'Correo electrónico o contraseña incorrectos.',
          });
        }

        const token = app.jwt.sign(
          {
            sub: user.id,
            email: user.email,
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
