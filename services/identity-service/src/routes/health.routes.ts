
import type { FastifyInstance } from 'fastify';

import { prisma } from '../lib/prisma.js';

export const healthRoutes = async (
  app: FastifyInstance,
): Promise<void> => {
  app.get(
    '/health',
    {
      schema: {
        tags: ['Health'],
        summary: 'Consultar el estado del servicio',
        description:
          'Comprueba que Identity Service está activo y puede responder solicitudes.',
        response: {
          200: {
            description: 'El servicio está funcionando correctamente.',
            type: 'object',
            properties: {
              status: { type: 'string', example: 'ok' },
              service: { type: 'string', example: 'identity-service' },
            },
            required: ['status', 'service'],
          },
        },
      },
    },
    async () => {
      return {
        status: 'ok',
        service: 'identity-service',
      };
    },
  );

  app.get(
    '/health/db',
    {
      schema: {
        tags: ['Health'],
        summary: 'Comprobar la conexión a PostgreSQL',
        description:
          'Ejecuta una consulta sencilla para verificar la disponibilidad de la base de datos.',
        response: {
          200: {
            description: 'La base de datos está conectada.',
            type: 'object',
            properties: {
              status: { type: 'string', example: 'ok' },
              service: { type: 'string', example: 'identity-service' },
              database: { type: 'string', example: 'connected' },
            },
            required: ['status', 'service', 'database'],
          },
          503: {
            description: 'La base de datos no está disponible.',
            type: 'object',
            properties: {
              status: { type: 'string', example: 'error' },
              service: { type: 'string', example: 'identity-service' },
              database: { type: 'string', example: 'disconnected' },
            },
            required: ['status', 'service', 'database'],
          },
        },
      },
    },
    async (_request, reply) => {
      try {
        await prisma.$queryRaw`SELECT 1`;

        return reply.send({
          status: 'ok',
          service: 'identity-service',
          database: 'connected',
        });
      } catch (error) {
        app.log.error(error, 'Database health check failed');

        return reply.code(503).send({
          status: 'error',
          service: 'identity-service',
          database: 'disconnected',
        });
      }
    },
  );
};
