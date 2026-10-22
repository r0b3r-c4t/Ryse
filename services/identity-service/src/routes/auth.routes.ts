import type { FastifyInstance } from 'fastify';
import { Prisma } from '@prisma/client';
import argon2 from 'argon2';
import { z } from 'zod';

import { prisma } from '../lib/prisma.js';

const registerSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  email: z.string().trim().email().max(254),
  password: z.string().min(12).max(128),
});

export const authRoutes = async (app: FastifyInstance): Promise<void> => {
  app.post(
    '/auth/register',
    {
      attachValidation: true,
      schema: {
        tags: ['Authentication'],
        summary: 'Registrar una cuenta',
        description:
          'Crea una cuenta con correo y contraseña. El nombre es opcional y el correo se guarda en minúsculas.',
        body: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              minLength: 1,
              maxLength: 100,
              description: 'Nombre visible de la persona.',
            },
            email: {
              type: 'string',
              format: 'email',
              maxLength: 254,
            },
            password: {
              type: 'string',
              minLength: 12,
              maxLength: 128,
            },
          },
          required: ['email', 'password'],
        },
        response: {
          201: {
            description: 'La cuenta se creó correctamente.',
            type: 'object',
            properties: {
              message: { type: 'string', example: 'Usuario registrado correctamente.' },
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string', example: 'clx1234567890' },
                  name: { type: 'string', nullable: true, example: 'Persona' },
                  email: { type: 'string', format: 'email', example: 'persona@example.com' },
                  createdAt: { type: 'string', format: 'date-time' },
                },
                required: ['id', 'name', 'email', 'createdAt'],
              },
            },
            required: ['message', 'user'],
          },
          400: {
            description: 'El cuerpo de la solicitud no cumple con los requisitos.',
            type: 'object',
            properties: {
              error: { type: 'string', example: 'VALIDATION_ERROR' },
              message: { type: 'string' },
              details: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    field: { type: 'string' },
                    message: { type: 'string' },
                  },
                  required: ['field', 'message'],
                },
              },
            },
            required: ['error', 'message', 'details'],
          },
          409: {
            description: 'Ya existe una cuenta con ese correo electrónico.',
            type: 'object',
            properties: {
              error: { type: 'string', example: 'EMAIL_ALREADY_REGISTERED' },
              message: { type: 'string' },
            },
            required: ['error', 'message'],
          },
          500: {
            description: 'Ocurrió un error inesperado al crear la cuenta.',
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
      const validation = registerSchema.safeParse(request.body);

      if (!validation.success) {
        return reply.code(400).send({
          error: 'VALIDATION_ERROR',
          message: 'Los datos proporcionados no son válidos.',
          details: validation.error.issues.map((issue) => ({
            field: issue.path.join('.'),
            message: issue.message,
          })),
        });
      }

      const { name, password } = validation.data;
      const email = validation.data.email.toLowerCase();

      try {
        const passwordHash = await argon2.hash(password, {
          type: argon2.argon2id,
          memoryCost: 19456,
          timeCost: 2,
          parallelism: 1,
        });

        const user = await prisma.user.create({
          data: {
            name,
            email,
            passwordHash,
          },
          select: {
            id: true,
            name: true,
            email: true,
            createdAt: true,
          },
        });

        return reply.code(201).send({
          message: 'Usuario registrado correctamente.',
          user,
        });
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          return reply.code(409).send({
            error: 'EMAIL_ALREADY_REGISTERED',
            message: 'Este correo electrónico ya está registrado.',
          });
        }

        request.log.error({ err: error }, 'Failed to register user');

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Ocurrió un error al registrar el usuario.',
        });
      }
    },
  );
};
