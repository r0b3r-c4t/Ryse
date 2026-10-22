import 'dotenv/config';

import Fastify from 'fastify';
import jwt from '@fastify/jwt';
import { z } from 'zod';
import {
  serializerCompiler,
  validatorCompiler,
} from '@fastify/type-provider-zod';

import { sessionRoutes } from './routes/session.routes.js'
import { registerSwagger } from './plugins/swagger.js';
import { healthRoutes } from './routes/health.routes.js';
import { authRoutes } from './routes/auth.routes.js';
import { registerAuthentication } from './plugins/authenticate.js';
import { meRoutes } from './routes/me.routes.js';

const envSchema = z.object({
  HOST: z.string().min(1),
  PORT: z.coerce.number().int().min(1).max(65535),
  JWT_SECRET: z.string().min(1),
});

const env = envSchema.parse(process.env);

const app = Fastify({
  logger: true,
});

app.setValidatorCompiler(validatorCompiler);
app.setSerializerCompiler(serializerCompiler);

const start = async (): Promise<void> => {
  try {
    await app.register(jwt, {
      secret: env.JWT_SECRET,
    });

    await registerAuthentication(app);
    await registerSwagger(app);

    await app.register(healthRoutes);
    await app.register(authRoutes);
    await app.register(sessionRoutes);
    await app.register(meRoutes);

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
│                  RYSE IDENTITY               │
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
