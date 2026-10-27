import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

const meResponseSchema = z.object({
  id: z.string().meta({ example: 'clx1234567890' }),
  email: z.email().meta({ example: 'persona@example.com' }),
});

const errorResponseSchema = z.object({
  error: z.string().meta({ example: 'UNAUTHORIZED' }),
  message: z.string(),
});

export const meRoutes = async (app: FastifyInstance): Promise<void> => {
  app.get(
    '/auth/me',
    {
      preHandler: app.authenticate,
      schema: {
        tags: ['Identity'],
        summary: 'Consultar la identidad actual',
        description:
          'Devuelve el identificador y el correo del usuario asociado al token JWT.',
        security: [{ BearerAuth: [] }],
        response: {
          200: meResponseSchema.meta({
            description: 'Identidad del usuario autenticado.',
          }),
          401: errorResponseSchema.meta({
            description: 'No se proporcionó un token válido.',
          }),
        },
      },
    },
    async (request, reply) => {
      const payload = request.user;

      return reply.send({
        id: payload.sub,
        email: payload.email,
      });
    },
  );
};
