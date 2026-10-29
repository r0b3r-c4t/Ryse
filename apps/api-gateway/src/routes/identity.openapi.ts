import type { FastifyContextConfig, FastifySchema } from 'fastify';

type DocumentationSchema = Pick<FastifySchema, 'body' | 'params' | 'response'>;

export const documentIdentityRoute = (
  documentationSchema: DocumentationSchema,
): FastifyContextConfig => ({
  swaggerTransform: ({ schema, url }) => ({
    schema: {
      ...schema,
      ...documentationSchema,
    },
    url,
  }),
});

export const messageResponseSchema = {
  type: 'object',
  properties: {
    message: { type: 'string' },
  },
  required: ['message'],
} as const;

export const errorResponseSchema = {
  type: 'object',
  properties: {
    error: { type: 'string' },
    message: { type: 'string' },
  },
  required: ['error', 'message'],
} as const;

export const validationErrorResponseSchema = {
  type: 'object',
  properties: {
    error: { type: 'string', const: 'VALIDATION_ERROR' },
    message: { type: 'string' },
    details: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          field: { type: 'string' },
          message: { type: 'string' },
        },
        required: ['field', 'message'],
      },
    },
  },
  required: ['error', 'message', 'details'],
} as const;

export const passwordSchema = {
  type: 'string',
  minLength: 8,
  maxLength: 128,
} as const;

export const emailSchema = {
  type: 'string',
  format: 'email',
} as const;
