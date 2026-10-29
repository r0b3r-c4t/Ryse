import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import {
  documentIdentityRoute,
  emailSchema,
  errorResponseSchema,
  messageResponseSchema,
  passwordSchema,
  validationErrorResponseSchema,
} from './identity.openapi.js';

interface IdentityRoutesOptions {
  identityServiceUrl: string;
}

const getServiceUrl = (baseUrl: string): string => baseUrl.replace(/\/$/, '');

const forwardToIdentityService = async (
  request: FastifyRequest,
  reply: FastifyReply,
  baseUrl: string,
  path: string,
  init?: RequestInit,
): Promise<void> => {
  const headers = new Headers(init?.headers);

  if (request.headers.authorization) {
    headers.set('authorization', request.headers.authorization);
  }

  const response = await fetch(`${getServiceUrl(baseUrl)}${path}`, {
    ...init,
    headers,
  });

  const contentType = response.headers.get('content-type');

  if (contentType) {
    reply.header('content-type', contentType);
  }

  const payload = await response.text();

  reply.code(response.status);

  if (!payload) {
    await reply.send();
    return;
  }

  if (contentType?.includes('application/json')) {
    await reply.send(JSON.parse(payload));
    return;
  }

  await reply.send(payload);
};

export const identityRoutes = async (
  app: FastifyInstance,
  options: IdentityRoutesOptions,
): Promise<void> => {
  const baseUrl = getServiceUrl(options.identityServiceUrl);

  app.get(
    '/api/v1/identity/health',
    {
      schema: {
        tags: ['Health'],
        summary: 'Consultar el estado del servicio de identidad',
        description: 'Reenvía la comprobación de salud del Identity Service.',
      },
      config: documentIdentityRoute({
        response: {
          200: {
            type: 'object',
            properties: {
              status: { type: 'string' },
              service: { type: 'string' },
            },
            required: ['status', 'service'],
          },
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(request, reply, baseUrl, '/health');
    },
  );

  app.post(
    '/api/v1/identity/auth/register',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Registrar una cuenta',
        description: 'Reenvía el registro de usuario al Identity Service.',
      },
      config: documentIdentityRoute({
        body: {
          type: 'object',
          properties: {
            name: { type: 'string', minLength: 1, maxLength: 100 },
            username: {
              type: 'string',
              minLength: 3,
              maxLength: 30,
              pattern: '^[a-z0-9_]+$',
            },
            email: { ...emailSchema, maxLength: 254 },
            password: passwordSchema,
          },
          required: ['username', 'email', 'password'],
        },
        response: {
          201: {
            type: 'object',
            properties: {
              message: { type: 'string' },
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  name: { type: 'string', nullable: true },
                  username: {
                    type: 'string',
                    minLength: 3,
                    maxLength: 30,
                    pattern: '^[a-z0-9_]+$',
                  },
                  email: emailSchema,
                  createdAt: { type: 'string', format: 'date-time' },
                },
                required: ['id', 'name', 'username', 'email', 'createdAt'],
              },
            },
            required: ['message', 'user'],
          },
          400: validationErrorResponseSchema,
          409: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(request, reply, baseUrl, '/auth/register', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(request.body),
      });
    },
  );

  app.post(
    '/api/v1/identity/auth/login',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Iniciar sesión',
        description: 'Reenvía las credenciales al Identity Service y devuelve su respuesta.',
      },
      config: documentIdentityRoute({
        body: {
          type: 'object',
          properties: {
            email: { ...emailSchema, maxLength: 254 },
            password: { type: 'string', minLength: 1, maxLength: 128 },
          },
          required: ['email', 'password'],
        },
        response: {
          200: {
            type: 'object',
            properties: {
              message: { type: 'string' },
              accessToken: { type: 'string' },
              tokenType: { type: 'string', const: 'Bearer' },
              expiresIn: { type: 'integer' },
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  name: { type: 'string', nullable: true },
                  email: emailSchema,
                },
                required: ['id', 'name', 'email'],
              },
            },
            required: ['message', 'accessToken', 'tokenType', 'expiresIn', 'user'],
          },
          400: validationErrorResponseSchema,
          401: errorResponseSchema,
          403: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(request, reply, baseUrl, '/auth/login', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(request.body),
      });
    },
  );

  app.get(
    '/api/v1/identity/auth/me',
    {
      schema: {
        tags: ['Identity'],
        summary: 'Consultar la identidad actual',
        description: 'Reenvía la petición autenticada al Identity Service.',
        security: [{ BearerAuth: [] }],
      },
      config: documentIdentityRoute({
        response: {
          200: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              email: emailSchema,
            },
            required: ['id', 'email'],
          },
          401: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(request, reply, baseUrl, '/auth/me', {
        method: 'GET',
      });
    },
  );

  app.get(
    '/api/v1/identity/auth/sessions',
    {
      schema: {
        tags: ['Sessions'],
        summary: 'Listar sesiones activas',
        description:
          'Reenvía la consulta de sesiones activas al Identity Service.',
        security: [{ BearerAuth: [] }],
      },
      config: documentIdentityRoute({
        response: {
          200: {
            type: 'object',
            properties: {
              sessions: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    userAgent: { type: 'string', nullable: true },
                    ipAddress: { type: 'string', nullable: true },
                    createdAt: { type: 'string', format: 'date-time' },
                    lastUsedAt: {
                      type: 'string',
                      nullable: true,
                      format: 'date-time',
                    },
                    expiresAt: { type: 'string', format: 'date-time' },
                    isCurrent: { type: 'boolean' },
                  },
                  required: [
                    'id',
                    'userAgent',
                    'ipAddress',
                    'createdAt',
                    'lastUsedAt',
                    'expiresAt',
                    'isCurrent',
                  ],
                },
              },
            },
            required: ['sessions'],
          },
          401: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(
        request,
        reply,
        baseUrl,
        '/auth/sessions',
        {
          method: 'GET',
        },
      );
    },
  );

  app.delete(
    '/api/v1/identity/auth/sessions/:sessionId',
    {
      schema: {
        tags: ['Sessions'],
        summary: 'Revocar una sesión específica',
        description:
          'Reenvía la solicitud para revocar una sesión al Identity Service.',
        security: [{ BearerAuth: [] }],
      },
      config: documentIdentityRoute({
        params: {
          type: 'object',
          properties: {
            sessionId: { type: 'string', minLength: 1 },
          },
          required: ['sessionId'],
        },
        response: {
          200: messageResponseSchema,
          400: errorResponseSchema,
          401: errorResponseSchema,
          404: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      const { sessionId } = request.params as { sessionId: string };

      await forwardToIdentityService(
        request,
        reply,
        baseUrl,
        `/auth/sessions/${encodeURIComponent(sessionId)}`,
        {
          method: 'DELETE',
        },
      );
    },
  );

  app.delete(
    '/api/v1/identity/auth/sessions',
    {
      schema: {
        tags: ['Sessions'],
        summary: 'Revocar las demás sesiones',
        description:
          'Reenvía la solicitud autenticada para revocar todas las demás sesiones y sus refresh tokens, conservando la sesión actual.',
        security: [{ BearerAuth: [] }],
      },
      config: documentIdentityRoute({
        response: {
          200: {
            type: 'object',
            properties: {
              message: { type: 'string' },
              revokedCount: { type: 'integer', minimum: 0 },
            },
            required: ['message', 'revokedCount'],
          },
          401: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(
        request,
        reply,
        baseUrl,
        '/auth/sessions',
        {
          method: 'DELETE',
        },
      );
    },
  );

  app.post(
    '/api/v1/identity/auth/logout',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Cerrar sesión',
        description:
          'Reenvía la solicitud autenticada al Identity Service para cerrar la sesión.',
        security: [{ BearerAuth: [] }],
      },
      config: documentIdentityRoute({
        response: {
          200: messageResponseSchema,
          401: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(request, reply, baseUrl, '/auth/logout', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(request.body ?? {}),
      });
    },
  );
  app.post(
    '/api/v1/identity/auth/email-verification/request',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Solicitar verificación de correo',
        description:
          'Reenvía la solicitud de verificación de correo al Identity Service.',
      },
      config: documentIdentityRoute({
        body: {
          type: 'object',
          properties: {
            email: { ...emailSchema, maxLength: 320 },
          },
          required: ['email'],
        },
        response: {
          200: messageResponseSchema,
          400: validationErrorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(
        request,
        reply,
        baseUrl,
        '/auth/email-verification/request',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify(request.body),
        },
      );
    },
  );

  app.post(
    '/api/v1/identity/auth/email-verification/confirm',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Confirmar correo electrónico',
        description:
          'Reenvía el token de verificación al Identity Service.',
      },
      config: documentIdentityRoute({
        body: {
          type: 'object',
          properties: {
            token: { type: 'string', minLength: 1, maxLength: 512 },
          },
          required: ['token'],
        },
        response: {
          200: messageResponseSchema,
          400: {
            oneOf: [
              validationErrorResponseSchema,
              {
                type: 'object',
                properties: {
                  error: {
                    type: 'string',
                    const: 'INVALID_OR_EXPIRED_TOKEN',
                  },
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
              },
            ],
          },
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(
        request,
        reply,
        baseUrl,
        '/auth/email-verification/confirm',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify(request.body),
        },
      );
    },
  );

  app.post(
    '/api/v1/identity/auth/password-reset/request',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Solicitar recuperación de contraseña',
        description:
          'Reenvía la solicitud de recuperación al Identity Service.',
      },
      config: documentIdentityRoute({
        body: {
          type: 'object',
          properties: {
            email: { ...emailSchema, maxLength: 254 },
          },
          required: ['email'],
        },
        response: {
          200: messageResponseSchema,
          400: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(
        request,
        reply,
        baseUrl,
        '/auth/password-reset/request',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify(request.body),
        },
      );
    },
  );

  app.post(
    '/api/v1/identity/auth/password-reset/confirm',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Confirmar recuperación de contraseña',
        description:
          'Reenvía el token y la nueva contraseña al Identity Service.',
      },
      config: documentIdentityRoute({
        body: {
          type: 'object',
          properties: {
            token: { type: 'string', minLength: 1, maxLength: 512 },
            password: passwordSchema,
          },
          required: ['token', 'password'],
        },
        response: {
          200: messageResponseSchema,
          400: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(
        request,
        reply,
        baseUrl,
        '/auth/password-reset/confirm',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify(request.body),
        },
      );
    },
  );

  app.post(
    '/api/v1/identity/auth/password/change',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Cambiar contraseña',
        description:
          'Cambia la contraseña sin cerrar sesiones existentes. Para cerrarlas después, usa DELETE /api/v1/identity/auth/sessions; la sesión actual se conserva.',
        security: [{ BearerAuth: [] }],
      },
      config: documentIdentityRoute({
        body: {
          type: 'object',
          properties: {
            currentPassword: {
              type: 'string',
              minLength: 1,
              maxLength: 128,
            },
            newPassword: passwordSchema,
          },
          required: ['currentPassword', 'newPassword'],
        },
        response: {
          200: messageResponseSchema,
          400: errorResponseSchema,
          401: errorResponseSchema,
          500: errorResponseSchema,
        },
      }),
    },
    async (request, reply) => {
      await forwardToIdentityService(
        request,
        reply,
        baseUrl,
        '/auth/password/change',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify(request.body),
        },
      );
    },
  );

};
