
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { prisma } from '../lib/prisma.js';

const healthResponseSchema = z.object({
  status: z.string().meta({ example: 'ok' }),
  service: z.string().meta({ example: 'identity-service' }),
});

const databaseHealthResponseSchema = z.object({
  status: z.enum(['ok', 'error']),
  service: z.string().meta({ example: 'identity-service' }),
  database: z.enum(['connected', 'disconnected']),
});

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
          200: healthResponseSchema.meta({
            description: 'El servicio está funcionando correctamente.',
          }),
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
          200: databaseHealthResponseSchema.meta({
            description: 'La base de datos está conectada.',
          }),
          503: databaseHealthResponseSchema.meta({
            description: 'La base de datos no está disponible.',
          }),
        },
      },
    },
    async (_request, reply) => {
      try {
        await prisma.$queryRaw`SELECT 1`;

        return reply.code(200).send({
          status: 'ok',
          service: 'identity-service',
          database: 'connected',
        });
      } catch (error) {
        app.log.error({ err: error }, 'Database health check failed');

        return reply.code(503).send({
          status: 'error',
          service: 'identity-service',
          database: 'disconnected',
        });
      }
    },
  );
};
