import { z } from 'zod';

export const errorResponseSchema = z.object({
  error: z.string(),
  message: z.string(),
});

export const validationErrorSchema = z.object({
  error: z.literal('VALIDATION_ERROR'),
  message: z.string(),
  details: z.array(
    z.object({
      field: z.string(),
      message: z.string(),
    }),
  ),
});
