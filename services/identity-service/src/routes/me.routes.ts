import type { FastifyInstance } from 'fastify';

export const meRoutes = async (app: FastifyInstance): Promise<void> => {
  app.get(
    '/auth/me',
    {
      preHandler: app.authenticate,
      schema: {
        tags: ['Identity'],
        summary: 'Consultar la identidad actual',
        description: 'Devuelve el identificador y el correo del usuario asociado al token JWT.',
        security: [{ BearerAuth: [] }],
        response: {
          200: {
            description: 'Identidad del usuario autenticado.',
            type: 'object',
            properties: {
              id: { type: 'string', example: 'clx1234567890' },
              email: { type: 'string', format: 'email', example: 'persona@example.com' },
            },
            required: ['id', 'email'],
          },
          401: {
            description: 'No se proporcionó un token válido.',
            type: 'object',
            properties: {
              error: { type: 'string', example: 'UNAUTHORIZED' },
              message: { type: 'string' },
            },
            required: ['error', 'message'],
          },
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
