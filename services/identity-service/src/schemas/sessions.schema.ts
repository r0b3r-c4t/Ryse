import { z } from 'zod';

export const sessionItemSchema = z.object({
    id: z.string(),
    userAgent: z.string().nullable(),
    ipAddress: z.string().nullable(),
    createdAt: z.string().datetime(),
    lastUsedAt: z.string().datetime().nullable(),
    expiresAt: z.string().datetime(),
    isCurrent: z.boolean(),
});

export const sessionsResponseSchema = z.object({
    sessions: z.array(sessionItemSchema),
});
