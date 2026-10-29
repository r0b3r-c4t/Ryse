import 'dotenv/config';

// Dependencias externas
import cookie from '@fastify/cookie';
import { serializerCompiler, validatorCompiler } from '@fastify/type-provider-zod';
import Fastify from 'fastify';
import { z } from 'zod';

// Plugins
import { registerAuthentication } from './plugins/authenticate.js';
import { registerJwt } from './plugins/jwt.js';
import { registerSwagger } from './plugins/swagger.js';

// Rutas
import { authRoutes } from './routes/auth.routes.js';
import { emailVerificationRoutes } from './routes/email-verification.routes.js';
import { healthRoutes } from './routes/health.routes.js';
import { meRoutes } from './routes/me.routes.js';
import { passwordChangeRoutes } from './routes/password-change.routes.js';
import { passwordResetRoutes } from './routes/password-reset.routes.js';
import { refreshRoutes } from './routes/refresh.routes.js';
import { sessionRoutes } from './routes/session.routes.js';

const envSchema = z.object({
  HOST: z.string().min(1),
  PORT: z.coerce.number().int().min(1).max(65535),
  JWT_SECRET: z.string().min(1),
  RESEND_API_KEY: z.string().min(1),
  APP_URL: z.string().url(),
});

const env = envSchema.parse(process.env);

const app = Fastify({
  logger: true,
});

app.setValidatorCompiler(validatorCompiler);
app.setSerializerCompiler(serializerCompiler);

const start = async (): Promise<void> => {
  try {
    await app.register(cookie);
    registerJwt(app, env.JWT_SECRET);

    await registerAuthentication(app);
    await registerSwagger(app);

    await app.register(healthRoutes);
    await app.register(authRoutes);
    await app.register(emailVerificationRoutes);
    await app.register(passwordChangeRoutes);
    await app.register(passwordResetRoutes, {
      appUrl: env.APP_URL,
    });
    await app.register(sessionRoutes);
    await app.register(refreshRoutes);
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
