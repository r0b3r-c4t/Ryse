import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';
import argon2 from 'argon2';
import { z } from 'zod';
import {
  generateRefreshToken,
  hashRefreshToken,
} from '../lib/refresh-token.js';

import { prisma } from '../lib/prisma.js';

const REFRESH_COOKIE = 'ryse_refresh_token';

const refreshCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  path: '/auth',
};


const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .toLowerCase()
    .max(254)
    .pipe(z.email('El correo electrónico no es válido.')),
  password: z.string().min(1).max(128),
});

const loginResponseSchema = z.object({
  message: z.string().meta({ example: 'Inicio de sesión exitoso.' }),
  accessToken: z.string().meta({ description: 'Token JWT de acceso.' }),
  tokenType: z.string().meta({ example: 'Bearer' }),
  expiresIn: z.number().int().meta({
    example: 900,
    description: 'Duración del token en segundos.',
  }),
  user: z.object({
    id: z.string().meta({ example: 'clx1234567890' }),
    name: z.string().nullable().meta({ example: 'Persona' }),
    email: z.email().meta({ example: 'persona@example.com' }),
  }),
});

const errorResponseSchema = z.object({
  error: z.string(),
  message: z.string(),
});

export const sessionRoutes = async (
  app: FastifyInstance,
): Promise<void> => {
  app.withTypeProvider<ZodTypeProvider>().post(
    '/auth/login',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Iniciar sesión',
        description:
          'Valida las credenciales y devuelve un token de acceso JWT válido por 15 minutos.',
        body: loginSchema,
        response: {
          200: loginResponseSchema.meta({
            description: 'Las credenciales son válidas.',
          }),
          400: errorResponseSchema.meta({
            description:
              'El cuerpo de la solicitud no cumple con los requisitos.',
          }),
          401: errorResponseSchema.meta({
            description: 'El correo o la contraseña son incorrectos.',
          }),
          403: errorResponseSchema.meta({
            description: 'La cuenta no está disponible para iniciar sesión.',
          }),
          500: errorResponseSchema.meta({
            description: 'Ocurrió un error inesperado al iniciar sesión.',
          }),
        },
      },
    },
    async (request, reply) => {
      const { email, password } = request.body;

      try {
        const user = await prisma.user.findUnique({
          where: { email },
        });

        if (!user) {
          return reply.code(401).send({
            error: 'INVALID_CREDENTIALS',
            message: 'Correo electrónico o contraseña incorrectos.',
          });
        }

        if (user.status !== 'ACTIVE') {
          return reply.code(403).send({
            error: 'ACCOUNT_NOT_ACTIVE',
            message: 'La cuenta no está disponible para iniciar sesión.',
          });
        }

        const passwordMatches = await argon2.verify(
          user.passwordHash,
          password,
        );

        if (!passwordMatches) {
          return reply.code(401).send({
            error: 'INVALID_CREDENTIALS',
            message: 'Correo electrónico o contraseña incorrectos.',
          });
        }

        const now = new Date();

        const sessionExpiresAt = new Date(
          now.getTime() + 30 * 24 * 60 * 60 * 1000,
        );

        const refreshToken = generateRefreshToken();
        const refreshTokenHash = hashRefreshToken(refreshToken);

        const session = await prisma.$transaction(async (tx) => {
          const newSession = await tx.session.create({
            data: {
              userId: user.id,
              expiresAt: sessionExpiresAt,
            },
          });

          await tx.refreshToken.create({
            data: {
              sessionId: newSession.id,
              tokenHash: refreshTokenHash,
              expiresAt: sessionExpiresAt,
            },
          });

          return newSession;
        });

        const token = app.jwt.sign(
          {
            sub: user.id,
            email: user.email,
            sid: session.id,
          },
          {
            expiresIn: '15m',
          },
        );

        reply.setCookie(REFRESH_COOKIE, refreshToken, {
          ...refreshCookieOptions,
          maxAge: 30 * 24 * 60 * 60,
        });

        return reply.code(200).send({
          message: 'Inicio de sesión exitoso.',
          accessToken: token,
          tokenType: 'Bearer',
          expiresIn: 900,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
          },
        });
      } catch (error) {
        request.log.error({ err: error }, 'Failed to log in user');

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Ocurrió un error al iniciar sesión.',
        });
      }
    },
  );

  app.withTypeProvider<ZodTypeProvider>().post(
    '/auth/logout',
    {
      preHandler: app.authenticate,
      schema: {
        tags: ['Authentication'],
        summary: 'Cerrar sesión',
        description:
          'Revoca la sesión actual y sus refresh tokens asociados.',
        security: [{ BearerAuth: [] }],
        response: {
          200: z.object({
            message: z.string(),
          }).meta({
            description: 'La sesión se cerró correctamente.',
          }),
          401: errorResponseSchema.meta({
            description:
              'El token es inválido o la sesión expiró o fue revocada.',
          }),
          500: errorResponseSchema.meta({
            description: 'No fue posible cerrar la sesión.',
          }),
        },
      },
    },
    async (request, reply) => {
      const userId = request.user.sub;
      const sessionId = request.user.sid;
      const revokedAt = new Date();

      try {
        const sessionRevoked = await prisma.$transaction(
          async (tx) => {
            const result = await tx.session.updateMany({
              where: {
                id: sessionId,
                userId,
                revokedAt: null,
                expiresAt: { gt: revokedAt },
              },
              data: { revokedAt },
            });

            if (result.count !== 1) {
              return false;
            }

            await tx.refreshToken.updateMany({
              where: {
                sessionId,
                revokedAt: null,
              },
              data: { revokedAt },
            });

            return true;
          },
        );

        if (!sessionRevoked) {
          reply.clearCookie(REFRESH_COOKIE, refreshCookieOptions);

          return reply.code(401).send({
            error: 'UNAUTHORIZED',
            message: 'La sesión ya expiró o fue cerrada.',
          });
        }
        reply.clearCookie(REFRESH_COOKIE, refreshCookieOptions);

        return reply.code(200).send({
          message: 'Sesión cerrada correctamente.',
        });
      } catch (error) {
        request.log.error(
          { err: error },
          'Error al cerrar la sesión',
        );

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'No fue posible cerrar la sesión.',
        });
      }
    },
  );
};
