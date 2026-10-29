# Pruebas de integración de contraseña y sesiones

Estas pruebas usan PostgreSQL real mediante el cliente Prisma y ejercitan las
rutas del Identity Service, además del reenvío del API Gateway. Node.js `node:test`
y el cargador `tsx` ya instalados en el monorepo ejecutan la suite, sin runner o
dependencias adicionales.

## Preparar una base aislada

Provisiona una instancia de PostgreSQL de pruebas independiente de desarrollo y
producción. Crea en ella una base llamada exactamente `ryse_identity_test`; el
test rechaza cualquier otro nombre. No apuntes `TEST_DATABASE_URL` al `.env` del
proyecto.

Aplica las migraciones a esa base y ejecuta la suite:

```sh
DATABASE_URL='postgresql://USER:PASSWORD@HOST:PORT/ryse_identity_test?schema=public' \
  pnpm --filter @ryse/identity-service exec prisma migrate deploy

TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST:PORT/ryse_identity_test?schema=public' \
  pnpm --filter @ryse/identity-service test
```

Las pruebas crean usuarios con direcciones `example.test` y los eliminan al
finalizar. La eliminación está acotada a los identificadores generados por la
propia suite; las relaciones en cascada limpian sesiones, tokens y solicitudes
de recuperación.

Si `TEST_DATABASE_URL` no está definido, Node marca la prueba como omitida. No
se sustituye por `DATABASE_URL` ni por las credenciales del entorno local.
