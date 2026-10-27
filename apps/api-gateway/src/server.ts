import 'dotenv/config';

import Fastify from 'fastify';
import { z } from 'zod';

import { registerSwagger } from './plugins/swagger.js';
import { identityRoutes } from './routes/identity.routes.js';

const envSchema = z.object({
  HOST: z.string().min(1),
  PORT: z.coerce.number().int().min(1).max(65535),
  IDENTITY_SERVICE_URL: z.string().url(),
});

const env = envSchema.parse(process.env);

const app = Fastify({
  logger: true,
});

app.get(
  '/health',
  {
    schema: {
      tags: ['Health'],
      summary: 'Consultar el estado del API Gateway',
      response: {
        200: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            service: { type: 'string' },
          },
          required: ['status', 'service'],
        },
      },
    },
  },
  async () => {
    return {
      status: 'ok',
      service: 'api-gateway',
    };
  },
);

const start = async (): Promise<void> => {
  try {
    await registerSwagger(app);

    await app.register(identityRoutes, {
      identityServiceUrl: env.IDENTITY_SERVICE_URL,
    });

    await app.ready();

    app.log.info('\n' + app.printRoutes());

    await app.listen({
      host: env.HOST,
      port: env.PORT,
    });


    const address = `http://localhost:${env.PORT}`;
    const documentation = `${address}/docs`;

    console.log(`
┌──────────────────────────────────────────────┐
│                 RYSE API GATEWAY             │
├──────────────────────────────────────────────┤
│  Status:         Corriendo                   │
│  Port:           ${String(env.PORT).padEnd(27)} │
│  Server:         ${address.padEnd(27)} │
│  Documentation:  ${documentation.padEnd(27)} │
└──────────────────────────────────────────────┘
`);
  } catch (error) {
    app.log.error(error);
    process.exitCode = 1;
  }
};

void start();
