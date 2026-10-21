import 'dotenv/config';

import Fastify from 'fastify';
import { z } from 'zod';

const envSchema = z.object({
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
});

const env = envSchema.parse(process.env);

const app = Fastify({
  logger: true,
});

app.get('/health', async () => {
  return {
    status: 'ok',
    service: 'api-gateway',
  };
});

const start = async (): Promise<void> => {
  try {
    await app.listen({
      host: env.HOST,
      port: env.PORT,
    });
  } catch (error) {
    app.log.error(error);
    process.exitCode = 1;
  }
};

void start();
