import type { FastifyInstance } from 'fastify';
import jwt from '@fastify/jwt';

export const registerJwt = (
    app: FastifyInstance,
    secret: string,
): void => {
    app.register(jwt, {
        secret,
    });
};
