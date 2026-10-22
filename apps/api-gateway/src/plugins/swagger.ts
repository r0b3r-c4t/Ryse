
import type { FastifyInstance } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';

export const registerSwagger = async (
  app: FastifyInstance,
): Promise<void> => {
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'RYSE API Gateway',
        description: 'Punto de entrada HTTP para los microservicios de RYSE.',
        version: '0.1.0',
      },
      tags: [
        {
          name: 'Health',
          description: 'Estado del API Gateway.',
        },
        {
          name: 'Authentication',
          description: 'Registro e inicio de sesión.',
        },
        {
          name: 'Identity',
          description: 'Identidad y perfil del usuario autenticado.',
        },
      ],
      components: {
        securitySchemes: {
          BearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
          },
        },
      },
    },
  });

  await app.register(swaggerUI, {
    routePrefix: '/docs',
  });
};
