import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from '@fastify/type-provider-zod';

import {
    confirmEmailVerification,
    requestEmailVerification,
} from '../services/email-verification.service.js';
import {
    confirmEmailVerificationSchema,
    emailVerificationResponseSchema,
    requestEmailVerificationSchema,
    invalidVerificationTokenSchema,
} from '../schemas/email-verification.schema.js';
import {
    errorResponseSchema,
    validationErrorSchema,
} from '../schemas/common.schema.js';

export const emailVerificationRoutes = async (
    app: FastifyInstance,
): Promise<void> => {
    const routes = app.withTypeProvider<ZodTypeProvider>();

    routes.post(
        '/auth/email-verification/request',
        {
            attachValidation: true,
            schema: {
                tags: ['Authentication'],
                summary: 'Solicitar verificación de correo',
                description:
                    'Envía un enlace de verificación cuando el correo corresponde a una cuenta pendiente de verificar.',
                body: requestEmailVerificationSchema,
                response: {
                    200: emailVerificationResponseSchema,
                    400: validationErrorSchema,
                    500: errorResponseSchema,
                },
            },
        },
        async (request, reply) => {
            const validation = requestEmailVerificationSchema.safeParse(
                request.body,
            );

            if (request.validationError || !validation.success) {
                return reply.code(400).send({
                    error: 'VALIDATION_ERROR',
                    message: 'Los datos proporcionados no son válidos.',
                    details: validation.success
                        ? []
                        : validation.error.issues.map((issue) => ({
                            field: issue.path.join('.'),
                            message: issue.message,
                        })),
                });
            }

            try {
                await requestEmailVerification(validation.data);

                return reply.code(200).send({
                    message:
                        'Si el correo corresponde a una cuenta pendiente de verificación, recibirás un enlace.',
                });
            } catch (error) {
                request.log.error(
                    { err: error },
                    'Failed to request email verification',
                );

                return reply.code(500).send({
                    error: 'INTERNAL_SERVER_ERROR',
                    message: 'No se pudo procesar la solicitud.',
                });
            }
        },
    );

    routes.post(
        '/auth/email-verification/confirm',
        {
            attachValidation: true,
            schema: {
                tags: ['Authentication'],
                summary: 'Confirmar correo electrónico',
                description:
                    'Valida el token de verificación y marca el correo como verificado.',
                body: confirmEmailVerificationSchema,
                response: {
                    200: emailVerificationResponseSchema,
                    400: z.union([
                        validationErrorSchema,
                        invalidVerificationTokenSchema,
                    ]),
                    500: errorResponseSchema,
                },
            },
        },
        async (request, reply) => {
            const validation = confirmEmailVerificationSchema.safeParse(
                request.body,
            );

            if (request.validationError || !validation.success) {
                return reply.code(400).send({
                    error: 'VALIDATION_ERROR',
                    message: 'Los datos proporcionados no son válidos.',
                    details: validation.success
                        ? []
                        : validation.error.issues.map((issue) => ({
                            field: issue.path.join('.'),
                            message: issue.message,
                        })),
                });
            }

            try {
                const verified = await confirmEmailVerification(
                    validation.data.token,
                );

                if (!verified) {
                    return reply.code(400).send({
                        error: 'INVALID_OR_EXPIRED_TOKEN',
                        message:
                            'El enlace de verificación no es válido, ha vencido o ya fue utilizado.',
                        details: [],
                    });
                }

                return reply.code(200).send({
                    message: 'Correo electrónico verificado correctamente.',
                });
            } catch (error) {
                request.log.error(
                    { err: error },
                    'Failed to confirm email verification',
                );

                return reply.code(500).send({
                    error: 'INTERNAL_SERVER_ERROR',
                    message: 'No se pudo verificar el correo electrónico.',
                });
            }
        },
    );
};
