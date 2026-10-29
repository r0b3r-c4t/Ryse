import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';

import { prisma } from '../lib/prisma.js';
import { errorResponseSchema } from '../schemas/common.schema.js';
import { changePassword } from '../services/password-change.service.js';
import {
  changePasswordResponseSchema,
  changePasswordSchema,
} from '../schemas/password-change.schema.js';

export const passwordChangeRoutes = async (app: FastifyInstance): Promise<void> => {
  app.withTypeProvider<ZodTypeProvider>().post(
    '/auth/password/change',
    {
      preHandler: app.authenticate,
      attachValidation: true,
      schema: {
        tags: ['Identity'],
        summary: 'Cambiar contraseña autenticado',
        security: [{ BearerAuth: [] }],
        body: changePasswordSchema,
        response: {
          200: changePasswordResponseSchema,
          400: errorResponseSchema,
          401: errorResponseSchema,
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
        const result = await changePassword(prisma, {
          userId: request.user.sub,
          currentPassword: request.body.currentPassword,
          newPassword: request.body.newPassword,
        });

        if (result === 'invalid-current-password') {
          return reply.code(400).send({
            error: 'INVALID_CURRENT_PASSWORD',
            message: 'La contraseña actual es incorrecta.',
          });
        }

        return reply.code(200).send({
          message:
            'Tu contraseña se cambió correctamente. Las sesiones existentes siguen activas; puedes cerrar las demás desde la gestión de sesiones.',
        });
      } catch (error: unknown) {
        request.log.error({ err: error }, 'Error al cambiar contraseña');

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'No fue posible cambiar la contraseña.',
        });
      }
    },
  );
};
