import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { prisma } from '../lib/prisma.js';

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;

const unauthorized = async (
    reply: FastifyReply,
): Promise<void> => {
    await reply.code(401).send({
        error: 'UNAUTHORIZED',
        message: 'Tu sesión expiró o no es válida. Inicia sesión nuevamente.',
    });
};

export const authenticate = async (
    request: FastifyRequest,
    reply: FastifyReply,
): Promise<void> => {
    // 1. Verificar firma y expiración del access token.
    try {
        await request.jwtVerify();
    } catch {
        await unauthorized(reply);
        return;
    }

    const { sub: userId, sid: sessionId } = request.user;
    const now = new Date();

    try {
        // 2. Consultar la sesión y el estado del usuario.
        const session = await prisma.session.findUnique({
            where: { id: sessionId },
            include: {
                user: true,
            },
        });

        if (
            !session ||
            session.userId !== userId ||
            session.revokedAt !== null ||
            session.expiresAt <= now ||
            session.user.status !== 'ACTIVE'
        ) {
            await unauthorized(reply);
            return;
        }

        // 3. Comprobar el límite de inactividad.
        // Si nunca se registró actividad, usar la creación de la sesión.
        const lastActivity = session.lastUsedAt ?? session.createdAt;
        const inactiveFor = now.getTime() - lastActivity.getTime();

        if (inactiveFor >= IDLE_TIMEOUT_MS) {
            // Revocar la sesión y todos sus refresh tokens.
            await prisma.$transaction([
                prisma.session.updateMany({
                    where: {
                        id: session.id,
                        revokedAt: null,
                    },
                    data: {
                        revokedAt: now,
                    },
                }),
                prisma.refreshToken.updateMany({
                    where: {
                        sessionId: session.id,
                        revokedAt: null,
                    },
                    data: {
                        revokedAt: now,
                    },
                }),
            ]);

            await unauthorized(reply);
            return;
        }

        // 4. Registrar la actividad autenticada.
        const activityUpdate = await prisma.session.updateMany({
            where: {
                id: session.id,
                userId,
                revokedAt: null,
                expiresAt: { gt: now },
            },
            data: {
                lastUsedAt: now,
            },
        });

        if (activityUpdate.count !== 1) {
            await unauthorized(reply);
            return;
        }
    } catch (error) {
        request.log.error(
            { err: error },
            'Error al validar la sesión',
        );

        await reply.code(500).send({
            error: 'INTERNAL_SERVER_ERROR',
            message: 'No fue posible validar tu sesión.',
        });
    }
};

export const registerAuthentication = async (
    app: FastifyInstance,
): Promise<void> => {
    app.decorate('authenticate', authenticate);
};
