import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

export const authenticate = async (
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> => {
  try {
    await request.jwtVerify();
  } catch {
    await reply.code(401).send({
      error: 'UNAUTHORIZED',
      message: 'Debes iniciar sesión para acceder a este recurso.',
    });

    return;
  }
};

export const registerAuthentication = async (
  app: FastifyInstance,
): Promise<void> => {
  app.decorate('authenticate', authenticate);
};
