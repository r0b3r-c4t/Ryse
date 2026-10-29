import assert from 'node:assert/strict';
import { test } from 'node:test';

const testDatabaseUrl = process.env.TEST_DATABASE_URL;

test(
  'password and session lifecycle through Identity Service and API Gateway',
  {
    skip: testDatabaseUrl
      ? false
      : 'Define TEST_DATABASE_URL for isolated PostgreSQL integration tests.',
  },
  async (t) => {
    const databaseUrl = new URL(testDatabaseUrl!);
    const databaseName = decodeURIComponent(databaseUrl.pathname.slice(1));

    if (databaseName !== 'ryse_identity_test') {
      throw new Error('Tests only run against a database named exactly ryse_identity_test.');
    }

    process.env.DATABASE_URL = testDatabaseUrl;
    process.env.NODE_ENV = 'test';

    const [
      { default: Fastify },
      cookieModule,
      zodProvider,
      jwtModule,
      prismaModule,
      authModule,
      sessionModule,
      refreshModule,
      passwordChangeModule,
      passwordResetModule,
      cryptoModule,
      gatewayModule,
    ] = await Promise.all([
      import('fastify'),
      import('@fastify/cookie'),
      import('@fastify/type-provider-zod'),
      import('@fastify/jwt'),
      import('../src/lib/prisma.js'),
      import('../src/plugins/authenticate.js'),
      import('../src/routes/session.routes.js'),
      import('../src/routes/refresh.routes.js'),
      import('../src/routes/password-change.routes.js'),
      import('../src/routes/password-reset.routes.js'),
      import('../src/lib/crypto.js'),
      import('../../../apps/api-gateway/src/routes/identity.routes.js'),
    ]);

    const prisma = prismaModule.prisma;
    const secret = 'integration-test-only-secret';
    const identity = Fastify({ logger: false });
    identity.setValidatorCompiler(zodProvider.validatorCompiler);
    identity.setSerializerCompiler(zodProvider.serializerCompiler);
    await identity.register(cookieModule.default);
    identity.register(jwtModule.default, { secret });
    await authModule.registerAuthentication(identity);
    await identity.register(passwordResetModule.passwordResetRoutes, {
      appUrl: 'http://localhost:3000',
    });
    await identity.register(passwordChangeModule.passwordChangeRoutes);
    await identity.register(sessionModule.sessionRoutes);
    await identity.register(refreshModule.refreshRoutes);
    await identity.ready();

    const gateway = Fastify({ logger: false });
    await gateway.register(gatewayModule.identityRoutes, {
      identityServiceUrl: 'http://identity.test',
    });
    await gateway.ready();

    const originalFetch = globalThis.fetch;
    const fixtures: Array<{ userId: string }> = [];
    globalThis.fetch = async (input, init) => {
      const result = await identity.inject({
        method: init?.method,
        url: new URL(String(input)).pathname,
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
        payload: init?.body as string | undefined,
      });
      return new Response(result.body, {
        status: result.statusCode,
        headers: result.headers as HeadersInit,
      });
    };

    t.after(async () => {
      if (fixtures.length > 0) {
        await prisma.user.deleteMany({
          where: { id: { in: fixtures.map((fixture) => fixture.userId) } },
        });
      }
      globalThis.fetch = originalFetch;
      await gateway.close();
      await identity.close();
      await prisma.$disconnect();
    });

    await prisma.$connect();
    const databases = await prisma.$queryRaw<Array<{ name: string }>>`
      SELECT current_database() AS name
    `;
    assert.equal(databases[0].name, 'ryse_identity_test');

    const createAccount = async (suffix: string) => {
      const password = 'Initial-password-123';
      const user = await prisma.user.create({
        data: {
          email: `password-session-${suffix}@example.test`,
          username: `pw_session_${suffix}`,
          passwordHash: await cryptoModule.hashPassword(password),
        },
      });
      fixtures.push({ userId: user.id });
      const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
      const sessions = await Promise.all([
        prisma.session.create({
          data: { userId: user.id, expiresAt: expiry },
        }),
        prisma.session.create({
          data: { userId: user.id, expiresAt: expiry },
        }),
      ]);
      const refreshTokens = [
        cryptoModule.generateSecureToken(),
        cryptoModule.generateSecureToken(),
      ];
      await Promise.all(
        sessions.map((session, index) =>
          prisma.refreshToken.create({
            data: {
              sessionId: session.id,
              tokenHash: cryptoModule.hashToken(refreshTokens[index]),
              expiresAt: expiry,
            },
          }),
        ),
      );
      const accessToken = identity.jwt.sign(
        { sub: user.id, email: user.email, sid: sessions[0].id },
        { expiresIn: '15m' },
      );
      return { user, password, sessions, refreshTokens, accessToken };
    };

    const account = await createAccount(`a${Date.now()}`);
    const otherAccount = await createAccount(`b${Date.now()}`);
    const resetToken = cryptoModule.generateSecureToken();
    await prisma.passwordReset.create({
      data: {
        userId: account.user.id,
        tokenHash: cryptoModule.hashToken(resetToken),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    const auth = { authorization: `Bearer ${account.accessToken}` };

    const rejectedChange = await gateway.inject({
      method: 'POST',
      url: '/api/v1/identity/auth/password/change',
      headers: auth,
      payload: {
        currentPassword: 'incorrect-password',
        newPassword: 'Another-password-789',
      },
    });
    assert.equal(rejectedChange.statusCode, 400);
    const rejectedPolicy = await gateway.inject({
      method: 'POST',
      url: '/api/v1/identity/auth/password/change',
      headers: auth,
      payload: { currentPassword: account.password, newPassword: 'short' },
    });
    assert.equal(rejectedPolicy.statusCode, 400);
    const unchangedPassword = await prisma.user.findUniqueOrThrow({
      where: { id: account.user.id },
    });
    assert.equal(
      await cryptoModule.verifyPassword(unchangedPassword.passwordHash, account.password),
      true,
    );

    const change = await gateway.inject({
      method: 'POST',
      url: '/api/v1/identity/auth/password/change',
      headers: auth,
      payload: {
        currentPassword: account.password,
        newPassword: 'Replacement-password-456',
      },
    });
    assert.equal(change.statusCode, 200);
    const storedUser = await prisma.user.findUniqueOrThrow({
      where: { id: account.user.id },
    });
    assert.equal(
      await cryptoModule.verifyPassword(storedUser.passwordHash, 'Replacement-password-456'),
      true,
    );
    assert.equal(
      await cryptoModule.verifyPassword(storedUser.passwordHash, account.password),
      false,
    );
    assert.deepEqual(
      await prisma.session.findMany({
        where: { userId: account.user.id },
        orderBy: { id: 'asc' },
        select: { revokedAt: true },
      }),
      [{ revokedAt: null }, { revokedAt: null }],
    );
    const pendingReset = await prisma.passwordReset.findFirstOrThrow({
      where: { userId: account.user.id },
    });
    assert.ok(pendingReset.usedAt);

    const invalidCurrent = await gateway.inject({
      method: 'POST',
      url: '/api/v1/identity/auth/password/change',
      headers: auth,
      payload: {
        currentPassword: 'incorrect-password',
        newPassword: 'Another-password-789',
      },
    });
    assert.equal(invalidCurrent.statusCode, 400);
    const invalidNew = await gateway.inject({
      method: 'POST',
      url: '/api/v1/identity/auth/password/change',
      headers: auth,
      payload: { currentPassword: 'Replacement-password-456', newPassword: 'short' },
    });
    assert.equal(invalidNew.statusCode, 400);
    assert.equal(
      await cryptoModule.verifyPassword(storedUser.passwordHash, 'Replacement-password-456'),
      true,
    );

    const noAuth = await gateway.inject({
      method: 'DELETE',
      url: '/api/v1/identity/auth/sessions',
    });
    assert.equal(noAuth.statusCode, 401);

    const keepCurrent = await gateway.inject({
      method: 'GET',
      url: '/api/v1/identity/auth/sessions',
      headers: auth,
    });
    assert.equal(keepCurrent.statusCode, 200);
    assert.equal(
      JSON.parse(keepCurrent.body).sessions.filter((s: { isCurrent: boolean }) => s.isCurrent)
        .length,
      1,
    );

    // Without DELETE, both sessions remain usable, including their refresh tokens.
    const secondSessionRenewed = await identity.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { cookie: `ryse_refresh_token=${account.refreshTokens[1]}` },
    });
    assert.equal(secondSessionRenewed.statusCode, 200);
    const setCookie = secondSessionRenewed.headers['set-cookie'];
    const setCookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
    const rotatedSecondRefresh = setCookieHeader?.match(/ryse_refresh_token=([^;,]+)/)?.[1];
    assert.ok(rotatedSecondRefresh);
    const otherRefresh = await identity.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { cookie: `ryse_refresh_token=${otherAccount.refreshTokens[0]}` },
    });
    assert.equal(otherRefresh.statusCode, 200);

    // Client-supplied sessionId is ignored; only the authenticated sid is kept.
    const revoke = await gateway.inject({
      method: 'DELETE',
      url: '/api/v1/identity/auth/sessions',
      headers: auth,
      payload: { sessionId: account.sessions[1].id },
    });
    assert.equal(revoke.statusCode, 200);
    assert.equal(JSON.parse(revoke.body).revokedCount, 1);
    const accountSessions = await prisma.session.findMany({
      where: { userId: account.user.id },
      orderBy: { id: 'asc' },
    });
    assert.equal(accountSessions.find((s) => s.id === account.sessions[0].id)?.revokedAt, null);
    assert.ok(accountSessions.find((s) => s.id === account.sessions[1].id)?.revokedAt);
    assert.equal(
      await prisma.refreshToken.count({
        where: { sessionId: account.sessions[1].id, revokedAt: { not: null } },
      }),
      2,
    );
    const stillCurrent = await gateway.inject({
      method: 'GET',
      url: '/api/v1/identity/auth/sessions',
      headers: auth,
    });
    assert.equal(stillCurrent.statusCode, 200);
    const revokedRefresh = await identity.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { cookie: `ryse_refresh_token=${rotatedSecondRefresh}` },
    });
    assert.equal(revokedRefresh.statusCode, 401);
    const currentRefresh = await identity.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { cookie: `ryse_refresh_token=${account.refreshTokens[0]}` },
    });
    assert.equal(currentRefresh.statusCode, 200);
    assert.equal(
      await prisma.session.count({
        where: { userId: otherAccount.user.id, revokedAt: null },
      }),
      2,
    );
    const unaffectedUserRefresh = await identity.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { cookie: `ryse_refresh_token=${otherAccount.refreshTokens[1]}` },
    });
    assert.equal(unaffectedUserRefresh.statusCode, 200);

    const genericResetRequest = await gateway.inject({
      method: 'POST',
      url: '/api/v1/identity/auth/password-reset/request',
      payload: { email: `unknown-${Date.now()}@example.test` },
    });
    assert.equal(genericResetRequest.statusCode, 200);

    const recoveryToken = cryptoModule.generateSecureToken();
    await prisma.passwordReset.create({
      data: {
        userId: otherAccount.user.id,
        tokenHash: cryptoModule.hashToken(recoveryToken),
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    const recovery = await gateway.inject({
      method: 'POST',
      url: '/api/v1/identity/auth/password-reset/confirm',
      payload: { token: recoveryToken, password: 'Recovered-password-987' },
    });
    assert.equal(recovery.statusCode, 200);
    const recoveredUser = await prisma.user.findUniqueOrThrow({
      where: { id: otherAccount.user.id },
    });
    assert.equal(
      await cryptoModule.verifyPassword(recoveredUser.passwordHash, 'Recovered-password-987'),
      true,
    );
    assert.equal(
      await prisma.session.count({
        where: { userId: otherAccount.user.id, revokedAt: null },
      }),
      0,
    );
    assert.equal(
      await prisma.refreshToken.count({
        where: {
          session: { userId: otherAccount.user.id },
          revokedAt: { not: null },
        },
      }),
      4,
    );
    const reusedRecoveryToken = await gateway.inject({
      method: 'POST',
      url: '/api/v1/identity/auth/password-reset/confirm',
      payload: { token: recoveryToken, password: 'Other-password-654' },
    });
    assert.equal(reusedRecoveryToken.statusCode, 400);
  },
);
