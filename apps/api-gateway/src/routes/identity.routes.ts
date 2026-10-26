import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

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

  reply.code(response.status).send(payload);
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
    },
    async (request, reply) => {
      await forwardToIdentityService(request, reply, baseUrl, '/auth/me', {
        method: 'GET',
      });
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
};