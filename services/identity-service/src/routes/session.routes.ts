import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';
import { z } from 'zod';
import { sessionsResponseSchema } from '../schemas/sessions.schema.js';
import {
  generateSecureToken,
  verifyPassword,
  hashToken,
} from '../lib/crypto.js';
import {
  loginSchema,
  loginResponseSchema,
} from '../schemas/auth.schema.js';

import {
  errorResponseSchema,
  validationErrorSchema,
} from '../schemas/common.schema.js';

import { prisma } from '../lib/prisma.js';

const REFRESH_COOKIE = 'ryse_refresh_token';

const refreshCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  path: '/auth',
};

export const sessionRoutes = async (
  app: FastifyInstance,
): Promise<void> => {
  app.withTypeProvider<ZodTypeProvider>().post(
    '/auth/login',
    {
      attachValidation: true,
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
          400: validationErrorSchema.meta({
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
      const validation = loginSchema.safeParse(request.body);

      if (request.validationError || !validation.success) {
        const issues = validation.success
          ? []
          : validation.error.issues;

        return reply.code(400).send({
          error: 'VALIDATION_ERROR',
          message: 'Los datos proporcionados no son válidos.',
          details: issues.map((issue) => ({
            field: issue.path.join('.'),
            message: issue.message,
          })),
        });
      }

      const { email, password } = validation.data;

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

        const passwordMatches = await verifyPassword(
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

        const refreshToken = generateSecureToken();
        const refreshTokenHash = hashToken(refreshToken);

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

  app.withTypeProvider<ZodTypeProvider>().get(
    '/auth/sessions',
    {
      preHandler: app.authenticate,
      schema: {
        tags: ['Sessions'],
        summary: 'Listar sesiones activas',
        description:
          'Devuelve las sesiones activas del usuario autenticado e identifica la sesión actual.',
        security: [{ BearerAuth: [] }],
        response: {
          200: sessionsResponseSchema,
          401: errorResponseSchema,
          500: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const userId = request.user.sub;
      const currentSessionId = request.user.sid;
      const now = new Date();

      try {
        const sessions = await prisma.session.findMany({
          where: {
            userId,
            revokedAt: null,
            expiresAt: { gt: now },
          },
          orderBy: [
            { lastUsedAt: 'desc' },
            { createdAt: 'desc' },
          ],
          select: {
            id: true,
            userAgent: true,
            ipAddress: true,
            createdAt: true,
            lastUsedAt: true,
            expiresAt: true,
          },
        });

        return reply.code(200).send({
          sessions: sessions.map((session) => ({
            ...session,
            createdAt: session.createdAt.toISOString(),
            lastUsedAt: session.lastUsedAt?.toISOString() ?? null,
            expiresAt: session.expiresAt.toISOString(),
            isCurrent: session.id === currentSessionId,
          })),
        });
      } catch (error) {
        request.log.error(
          { err: error },
          'Error al consultar las sesiones activas',
        );

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'No fue posible consultar las sesiones activas.',
        });
      }
    },
  );

  app.delete(
    '/auth/sessions/:sessionId',
    {
      preHandler: app.authenticate,
      schema: {
        tags: ['Sessions'],
        summary: 'Revocar una sesión específica',
        description:
          'Revoca una sesión perteneciente al usuario autenticado y sus refresh tokens.',
        security: [{ BearerAuth: [] }],
        params: z.object({
          sessionId: z.string().min(1),
        }),
        response: {
          200: z.object({
            message: z.string(),
          }),
          400: errorResponseSchema,
          401: errorResponseSchema,
          404: errorResponseSchema,
          500: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const { sessionId } = request.params as { sessionId: string };
      const userId = request.user.sub;
      const revokedAt = new Date();

      try {
        const revoked = await prisma.$transaction(async (tx) => {
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
        });

        if (!revoked) {
          return reply.code(404).send({
            error: 'SESSION_NOT_FOUND',
            message: 'La sesión no existe o ya no está activa.',
          });
        }

        return reply.code(200).send({
          message: 'Sesión revocada correctamente.',
        });
      } catch (error) {
        request.log.error(
          { err: error },
          'Error al revocar una sesión',
        );

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'No fue posible revocar la sesión.',
        });
      }
    },
  ); 
  
  app.delete(
    '/auth/sessions',
    {
      preHandler: app.authenticate,
      schema: {
        tags: ['Sessions'],
        summary: 'Revocar las demás sesiones',
        description:
          'Revoca todas las sesiones activas del usuario autenticado, excepto la actual, e invalida sus refresh tokens.',
        security: [{ BearerAuth: [] }],
        response: {
          200: z.object({
            message: z.string(),
            revokedCount: z.number().int().nonnegative(),
          }),
          401: errorResponseSchema,
          500: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const userId = request.user.sub;
      const currentSessionId = request.user.sid;
      const revokedAt = new Date();

      try {
        const revokedCount = await prisma.$transaction(async (tx) => {
          const result = await tx.session.updateMany({
            where: {
              userId,
              id: { not: currentSessionId },
              revokedAt: null,
              expiresAt: { gt: revokedAt },
            },
            data: {
              revokedAt,
            },
          });

          await tx.refreshToken.updateMany({
            where: {
              session: {
                userId,
                id: { not: currentSessionId },
              },
              revokedAt: null,
            },
            data: {
              revokedAt,
            },
          });

          return result.count;
        });

        return reply.code(200).send({
          message: 'Las demás sesiones fueron revocadas correctamente.',
          revokedCount,
        });
      } catch (error) {
        request.log.error(
          { err: error },
          'Error al revocar las demás sesiones',
        );

        return reply.code(500).send({
          error: 'INTERNAL_SERVER_ERROR',
          message: 'No fue posible revocar las demás sesiones.',
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
