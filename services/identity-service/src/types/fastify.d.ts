
import type { FastifyReply, FastifyRequest } from 'fastify';

interface RyseJwtPayload {
  sub: string;
  email: string;
}

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => Promise<void>;
  }
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: RyseJwtPayload;
    user: RyseJwtPayload;
  }
}
