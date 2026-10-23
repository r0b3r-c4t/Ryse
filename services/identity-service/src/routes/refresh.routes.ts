
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';
import { z } from 'zod';

import { prisma } from '../lib/prisma.js';
import {
    generateRefreshToken,
    hashRefreshToken,
} from '../lib/refresh-token.js';

const REFRESH_COOKIE = 'ryse_refresh_token';
const SESSION_DURATION_SECONDS = 30 * 24 * 60 * 60;

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict' as const,
    path: '/auth',
};

const refreshResponseSchema = z.object({
    message: z.string(),
    accessToken: z.string(),
    tokenType: z.literal('Bearer'),
    expiresIn: z.number().int(),
});

const errorResponseSchema = z.object({
    error: z.string(),
    message: z.string(),
});

export const refreshRoutes = async (
    app: FastifyInstance,
): Promise<void> => {
    app.withTypeProvider<ZodTypeProvider>().post(
        '/auth/refresh',
        {
            schema: {
                tags: ['Authentication'],
                summary: 'Renovar sesión',
                description:
                    'Rota el refresh token almacenado en una cookie HttpOnly.',
                response: {
                    200: refreshResponseSchema,
                    401: errorResponseSchema,
                    500: errorResponseSchema,
                },
            },
        },
        async (request, reply) => {
            const rawToken = request.cookies[REFRESH_COOKIE];

            if (!rawToken) {
                return reply.code(401).send({
                    error: 'INVALID_REFRESH_TOKEN',
                    message: 'La sesión expiró o no es válida.',
                });
            }

            const now = new Date();
            const tokenHash = hashRefreshToken(rawToken);
            const replacementToken = generateRefreshToken();
            const replacementHash = hashRefreshToken(replacementToken);

            try {
                const result = await prisma.$transaction(async (tx) => {
                    const storedToken = await tx.refreshToken.findUnique({
                        where: { tokenHash },
                        include: {
                            session: {
                                include: {
                                    user: true,
                                },
                            },
                        },
                    });

                    if (!storedToken) {
                        return { kind: 'INVALID' as const };
                    }

                    const { session } = storedToken;

                    // Detectar el uso de un token que ya fue rotado.
                    if (storedToken.usedAt !== null) {
                        await tx.session.updateMany({
                            where: {
                                id: session.id,
                                revokedAt: null,
                            },
                            data: { revokedAt: now },
                        });

                        await tx.refreshToken.updateMany({
                            where: {
                                sessionId: session.id,
                                revokedAt: null,
                            },
                            data: { revokedAt: now },
                        });

                        return { kind: 'REUSE' as const };
                    }

                    if (
                        storedToken.revokedAt !== null ||
                        storedToken.expiresAt <= now ||
                        session.revokedAt !== null ||
                        session.expiresAt <= now ||
                        session.user.status !== 'ACTIVE'
                    ) {
                        return { kind: 'INVALID' as const };
                    }

                    // Solo una solicitud puede consumir el token.
                    const consumed = await tx.refreshToken.updateMany({
                        where: {
                            id: storedToken.id,
                            usedAt: null,
                            revokedAt: null,
                            expiresAt: { gt: now },
                        },
                        data: { usedAt: now },
                    });

                    if (consumed.count !== 1) {
                        // Comprobar si otra solicitud lo consumió primero.
                        const currentToken = await tx.refreshToken.findUnique({
                            where: { id: storedToken.id },
                        });

                        if (currentToken?.usedAt != null) {
                            await tx.session.updateMany({
                                where: {
                                    id: session.id,
                                    revokedAt: null,
                                },
                                data: { revokedAt: now },
                            });

                            await tx.refreshToken.updateMany({
                                where: {
                                    sessionId: session.id,
                                    revokedAt: null,
                                },
                                data: { revokedAt: now },
                            });

                            return { kind: 'REUSE' as const };
                        }

                        return { kind: 'INVALID' as const };
                    }

                    await tx.refreshToken.create({
                        data: {
                            sessionId: session.id,
                            tokenHash: replacementHash,
                            expiresAt: session.expiresAt,
                        },
                    });

                    await tx.session.update({
                        where: { id: session.id },
                        data: { lastUsedAt: now },
                    });

                    const accessToken = app.jwt.sign(
                        {
                            sub: session.user.id,
                            email: session.user.email,
                            sid: session.id,
                        },
                        { expiresIn: '15m' },
                    );

                    return {
                        kind: 'SUCCESS' as const,
                        accessToken,
                        sessionExpiresAt: session.expiresAt,
                    };
                });

                if (result.kind !== 'SUCCESS') {
                    reply.clearCookie(REFRESH_COOKIE, cookieOptions);

                    if (result.kind === 'REUSE') {
                        request.log.warn(
                            'Se detectó reutilización de un refresh token.',
                        );
                    }

                    return reply.code(401).send({
                        error: 'INVALID_REFRESH_TOKEN',
                        message: 'La sesión expiró o no es válida.',
                    });
                }

                const remainingSeconds = Math.max(
                    0,
                    Math.floor(
                        (result.sessionExpiresAt.getTime() - Date.now()) / 1000,
                    ),
                );

                reply.setCookie(REFRESH_COOKIE, replacementToken, {
                    ...cookieOptions,
                    maxAge: Math.min(
                        remainingSeconds,
                        SESSION_DURATION_SECONDS,
                    ),
                });

                return reply.code(200).send({
                    message: 'Sesión renovada correctamente.',
                    accessToken: result.accessToken,
                    tokenType: 'Bearer',
                    expiresIn: 900,
                });
            } catch (error) {
                request.log.error(
                    { err: error },
                    'Error al renovar la sesión',
                );

                return reply.code(500).send({
                    error: 'INTERNAL_SERVER_ERROR',
                    message: 'No fue posible renovar la sesión.',
                });
            }
        },
    );
};
