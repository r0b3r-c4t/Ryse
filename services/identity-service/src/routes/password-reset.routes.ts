import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';

import { prisma } from '../lib/prisma.js';
import { errorResponseSchema } from '../schemas/common.schema.js';
import { confirmPasswordReset, requestPasswordReset } from '../services/password-reset.service.js';
import {
  confirmPasswordResetSchema,
  passwordResetConfirmationResponseSchema,
  passwordResetResponseSchema,
  requestPasswordResetSchema,
} from '../schemas/password-reset.schema.js';

interface PasswordResetRoutesOptions {
  appUrl: string;
}

export const passwordResetRoutes = async (
  app: FastifyInstance,
  options: PasswordResetRoutesOptions,
): Promise<void> => {
  const server = app.withTypeProvider<ZodTypeProvider>();

  // Solicitar recuperación de contraseña.
  server.post(
    '/auth/password-reset/request',
    {
      attachValidation: true,
      schema: {
        tags: ['Identity'],
        summary: 'Solicitar recuperación de contraseña',
        description:
          'Envía un enlace de recuperación al correo ingresado, independientemente de su estado de verificación.',
        body: requestPasswordResetSchema,
        response: {
          200: passwordResetResponseSchema,
          400: errorResponseSchema,
          500: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      if (request.validationError) {
        return reply.code(400).send({
          error: 'VALIDATION_ERROR',
          message: 'Los datos de la solicitud no son válidos.',
        });
      }

      try {
        await requestPasswordReset(prisma, request.body.email, options.appUrl);

        // La respuesta no revela si existe la cuenta.
        return reply.code(200).send({
          message:
            'Si el correo está registrado, recibirás instrucciones para restablecer tu contraseña.',
        });
      } catch (error: unknown) {
        request.log.error({ err: error }, 'Error al solicitar recuperación de contraseña');

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'No fue posible procesar la solicitud.',
        });
      }
    },
  );

  // Confirmar recuperación con un token de un solo uso.
  server.post(
    '/auth/password-reset/confirm',
    {
      attachValidation: true,
      schema: {
        tags: ['Identity'],
        summary: 'Confirmar recuperación de contraseña',
        body: confirmPasswordResetSchema,
        response: {
          200: passwordResetConfirmationResponseSchema,
          400: errorResponseSchema,
          500: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      if (request.validationError) {
        return reply.code(400).send({
          error: 'VALIDATION_ERROR',
          message: 'Los datos de la solicitud no son válidos.',
        });
      }

      try {
        const confirmed = await confirmPasswordReset(
          prisma,
          request.body.token,
          request.body.password,
        );

        if (!confirmed) {
          return reply.code(400).send({
            error: 'INVALID_OR_EXPIRED_TOKEN',
            message: 'El enlace no es válido o ha expirado.',
          });
        }

        return reply.code(200).send({
          message: 'Tu contraseña se restableció correctamente. Inicia sesión nuevamente.',
        });
      } catch (error: unknown) {
        request.log.error({ err: error }, 'Error al confirmar recuperación de contraseña');

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'No fue posible restablecer la contraseña.',
        });
      }
    },
  );
};
