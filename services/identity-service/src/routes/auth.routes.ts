
import argon2 from 'argon2';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';
import { Prisma } from '@prisma/client';

import { prisma } from '../lib/prisma.js';
import {
  registerSchema,
  registerResponseSchema,
} from '../schemas/auth.schema.js';
import {
  errorResponseSchema,
  validationErrorSchema,
} from '../schemas/common.schema.js';

export const authRoutes = async (
  app: FastifyInstance,
): Promise<void> => {
  app.withTypeProvider<ZodTypeProvider>().post(
    '/auth/register',
    {
      attachValidation: true,
      schema: {
        tags: ['Authentication'],
        summary: 'Registrar una cuenta',
        description:
          'Crea una cuenta con nombre de usuario, correo y contraseña. El nombre visible es opcional.',
        body: registerSchema,
        response: {
          201: registerResponseSchema.meta({
            description: 'La cuenta se creó correctamente.',
          }),
          400: validationErrorSchema.meta({
            description: 'Los datos proporcionados no son válidos.',
          }),
          409: errorResponseSchema.meta({
            description:
              'El correo o el nombre de usuario ya están registrados.',
          }),
          500: errorResponseSchema.meta({
            description: 'Ocurrió un error inesperado.',
          }),
        },
      },
    },
    async (request, reply) => {
      const validation = registerSchema.safeParse(request.body);

      if (request.validationError || !validation.success) {
        const issues = validation.success
          ? []
          : validation.error.issues;

        return reply.code(400).send({
          error: 'VALIDATION_ERROR',
          message: 'Los datos proporcionados no son válidos.',
          details: issues.map((issue) => ({
            field: issue.path.join('.'),
            message: issue.message,
          })),
        });
      }

      const { name, username, email, password } = validation.data;

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
            username,
            email,
            passwordHash,
          },
          select: {
            id: true,
            name: true,
            username: true,
            email: true,
            createdAt: true,
          },
        });

        return reply.code(201).send({
          message: 'Usuario registrado correctamente.',
          user,
        });
      } catch (error) {
        if (
          error instanceof Prisma.PrismaClientKnownRequestError &&
          error.code === 'P2002'
        ) {
          const target = error.meta?.target;
          const fields = Array.isArray(target)
            ? target.join(' ').toLowerCase()
            : String(target ?? '').toLowerCase();

          if (fields.includes('username')) {
            return reply.code(409).send({
              error: 'USERNAME_ALREADY_REGISTERED',
              message: 'Este nombre de usuario ya está registrado.',
            });
          }

          if (fields.includes('email')) {
            return reply.code(409).send({
              error: 'EMAIL_ALREADY_REGISTERED',
              message: 'Este correo electrónico ya está registrado.',
            });
          }

          return reply.code(409).send({
            error: 'ACCOUNT_ALREADY_EXISTS',
            message:
              'No se pudo crear la cuenta porque uno de los datos únicos ya está registrado.',
          });
        }

        request.log.error({ err: error }, 'Failed to register user');

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Ocurrió un error al registrar la cuenta.',
        });
      }
    },
  );
};
