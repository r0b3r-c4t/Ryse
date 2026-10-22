import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import type { FastifyInstance } from 'fastify';
import { jsonSchemaTransform } from '@fastify/type-provider-zod';

export const registerSwagger = async (app: FastifyInstance): Promise<void> => {
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'RYSE Identity Service API',
        description: 'API para registro, autenticación y gestión de identidad de RYSE.',
        version: '0.1.0',
      },
      tags: [
        {
          name: 'Health',
          description: 'Estado del servicio y su conexión a la base de datos.',
        },
        {
          name: 'Authentication',
          description: 'Registro e inicio de sesión.',
        },
        {
          name: 'Identity',
          description: 'Información del usuario autenticado.',
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
    transform: jsonSchemaTransform,
  });

  await app.register(swaggerUI, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: true,
    },
  });
};
