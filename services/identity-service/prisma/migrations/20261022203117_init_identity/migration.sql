
BEGIN;

CREATE TYPE "AccountStatus" AS ENUM (
    'ACTIVE',
    'PENDING_DELETION'
);

-- 1. Usuarios
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "username" VARCHAR(30) NOT NULL,
    "passwordHash" VARCHAR(255) NOT NULL,
    "name" VARCHAR(100),
    "status" "AccountStatus" NOT NULL DEFAULT 'ACTIVE',
    "emailVerifiedAt" TIMESTAMPTZ(3),
    "avatarUrl" VARCHAR(2048),
    "avatarPublicId" VARCHAR(255),
    "deletionRequestedAt" TIMESTAMPTZ(3),
    "scheduledDeletionAt" TIMESTAMPTZ(3),
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "User_pkey"
        PRIMARY KEY ("id"),

    CONSTRAINT "User_email_key"
        UNIQUE ("email"),

    CONSTRAINT "User_username_key"
        UNIQUE ("username"),

    CONSTRAINT "User_email_normalized_check"
        CHECK (
            "email" = lower("email")
            AND "email" = btrim("email")
            AND length("email") > 0
        ),

    CONSTRAINT "User_username_normalized_check"
        CHECK (
            "username" = lower("username")
            AND "username" = btrim("username")
            AND length("username") > 0
        ),

    CONSTRAINT "User_deletion_state_consistency_check"
        CHECK (
            (
                "status" = 'ACTIVE'
                AND "deletionRequestedAt" IS NULL
                AND "scheduledDeletionAt" IS NULL
            )
            OR
            (
                "status" = 'PENDING_DELETION'
                AND "deletionRequestedAt" IS NOT NULL
                AND "scheduledDeletionAt" IS NOT NULL
                AND "scheduledDeletionAt" > "deletionRequestedAt"
            )
        )
);

CREATE INDEX "User_status_scheduledDeletionAt_idx"
    ON "User" ("status", "scheduledDeletionAt");


-- 2. Sesiones
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "userAgent" VARCHAR(512),
    "ipAddress" VARCHAR(45),
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMPTZ(3),
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,
    "revokedAt" TIMESTAMPTZ(3),

    CONSTRAINT "Session_pkey"
        PRIMARY KEY ("id"),

    CONSTRAINT "Session_expiration_after_creation_check"
        CHECK ("expiresAt" > "createdAt"),

    CONSTRAINT "Session_lastUsedAt_check"
        CHECK ("lastUsedAt" IS NULL OR "lastUsedAt" >= "createdAt"),

    CONSTRAINT "Session_revokedAt_check"
        CHECK ("revokedAt" IS NULL OR "revokedAt" >= "createdAt"),

    CONSTRAINT "Session_userId_fkey"
        FOREIGN KEY ("userId")
        REFERENCES "User" ("id")
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX "Session_userId_revokedAt_idx"
    ON "Session" ("userId", "revokedAt");

CREATE INDEX "Session_expiresAt_idx"
    ON "Session" ("expiresAt");


-- 3. Tokens de renovacion
CREATE TABLE "RefreshToken" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "tokenHash" VARCHAR(255) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,
    "usedAt" TIMESTAMPTZ(3),
    "revokedAt" TIMESTAMPTZ(3),

    CONSTRAINT "RefreshToken_pkey"
        PRIMARY KEY ("id"),

    CONSTRAINT "RefreshToken_tokenHash_key"
        UNIQUE ("tokenHash"),

    CONSTRAINT "RefreshToken_expiration_after_creation_check"
        CHECK ("expiresAt" > "createdAt"),

    CONSTRAINT "RefreshToken_usedAt_check"
        CHECK ("usedAt" IS NULL OR "usedAt" >= "createdAt"),

    CONSTRAINT "RefreshToken_revokedAt_check"
        CHECK ("revokedAt" IS NULL OR "revokedAt" >= "createdAt"),

    CONSTRAINT "RefreshToken_sessionId_fkey"
        FOREIGN KEY ("sessionId")
        REFERENCES "Session" ("id")
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX "RefreshToken_sessionId_revokedAt_idx"
    ON "RefreshToken" ("sessionId", "revokedAt");

CREATE INDEX "RefreshToken_expiresAt_idx"
    ON "RefreshToken" ("expiresAt");


-- 4. Verificacion de correo
CREATE TABLE "EmailVerification" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "codeHash" VARCHAR(255) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "consumedAt" TIMESTAMPTZ(3),
    "invalidatedAt" TIMESTAMPTZ(3),

    CONSTRAINT "EmailVerification_pkey"
        PRIMARY KEY ("id"),

    CONSTRAINT "EmailVerification_attemptCount_nonnegative_check"
        CHECK ("attemptCount" >= 0),

    CONSTRAINT "EmailVerification_expiration_after_creation_check"
        CHECK ("expiresAt" > "createdAt"),

    CONSTRAINT "EmailVerification_consumedAt_check"
        CHECK ("consumedAt" IS NULL OR "consumedAt" >= "createdAt"),

    CONSTRAINT "EmailVerification_invalidatedAt_check"
        CHECK ("invalidatedAt" IS NULL OR "invalidatedAt" >= "createdAt"),

    CONSTRAINT "EmailVerification_userId_fkey"
        FOREIGN KEY ("userId")
        REFERENCES "User" ("id")
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX "EmailVerification_userId_createdAt_idx"
    ON "EmailVerification" ("userId", "createdAt");

CREATE INDEX "EmailVerification_expiresAt_idx"
    ON "EmailVerification" ("expiresAt");


-- 5. Recuperacion de contrasena
CREATE TABLE "PasswordReset" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" VARCHAR(255) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,
    "usedAt" TIMESTAMPTZ(3),

    CONSTRAINT "PasswordReset_pkey"
        PRIMARY KEY ("id"),

    CONSTRAINT "PasswordReset_tokenHash_key"
        UNIQUE ("tokenHash"),

    CONSTRAINT "PasswordReset_expiration_after_creation_check"
        CHECK ("expiresAt" > "createdAt"),

    CONSTRAINT "PasswordReset_usedAt_check"
        CHECK ("usedAt" IS NULL OR "usedAt" >= "createdAt"),

    CONSTRAINT "PasswordReset_userId_fkey"
        FOREIGN KEY ("userId")
        REFERENCES "User" ("id")
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE INDEX "PasswordReset_userId_createdAt_idx"
    ON "PasswordReset" ("userId", "createdAt");

CREATE INDEX "PasswordReset_expiresAt_idx"
    ON "PasswordReset" ("expiresAt");


-- 6. Auditoria de seguridad
CREATE TABLE "SecurityAuditEvent" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "eventType" VARCHAR(100) NOT NULL,
    "occurredAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" VARCHAR(45),
    "userAgent" VARCHAR(512),
    "metadata" JSONB,

    CONSTRAINT "SecurityAuditEvent_pkey"
        PRIMARY KEY ("id"),

    CONSTRAINT "SecurityAuditEvent_userId_fkey"
        FOREIGN KEY ("userId")
        REFERENCES "User" ("id")
        ON DELETE SET NULL
        ON UPDATE CASCADE
);

CREATE INDEX "SecurityAuditEvent_userId_occurredAt_idx"
    ON "SecurityAuditEvent" ("userId", "occurredAt");

CREATE INDEX "SecurityAuditEvent_eventType_occurredAt_idx"
    ON "SecurityAuditEvent" ("eventType", "occurredAt");

COMMIT;
