import { z } from 'zod';

export const requestEmailVerificationSchema = z.object({
    email: z.string().trim().email().max(320),
});

export const confirmEmailVerificationSchema = z.object({
    token: z.string().min(1).max(512),
});

export const emailVerificationResponseSchema = z.object({
    message: z.string(),
});

export const invalidVerificationTokenSchema = z.object({
    error: z.literal('INVALID_OR_EXPIRED_TOKEN'),
    message: z.string(),
    details: z.array(
        z.object({
            field: z.string(),
            message: z.string(),
        }),
    ),
});
