import type { PrismaClient } from '@prisma/client';
import { generateSecureToken, hashPassword, hashToken } from '../lib/crypto.js';
import { sendEmail } from '../plugins/resend.js';

const PASSWORD_RESET_EXPIRATION_MINUTES = 30;

export async function requestPasswordReset(
  prisma: PrismaClient,
  email: string,
  appUrl: string,
): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { email },
  });

  // No revelamos si el correo está registrado o verificado.
  if (!user) {
    return;
  }

  const token = generateSecureToken();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_EXPIRATION_MINUTES * 60 * 1000);

  await prisma.$transaction(async (tx) => {
    // Serializamos las solicitudes de recuperación de la cuenta.
    await tx.$queryRaw`
      SELECT id FROM "User" WHERE id = ${user.id} FOR UPDATE
    `;

    const now = new Date();

    // Invalidamos las solicitudes anteriores pendientes.
    await tx.passwordReset.updateMany({
      where: {
        userId: user.id,
        usedAt: null,
      },
      data: { usedAt: now },
    });

    await tx.passwordReset.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt,
      },
    });
  });

  const resetUrl = new URL('/reset-password', appUrl);
  resetUrl.searchParams.set('token', token);

  try {
    await sendEmail({
      to: user.email,
      subject: 'Restablece tu contraseña de RYSE',
      html: `
        <h1>Restablece tu contraseña</h1>
        <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta RYSE.</p>
        <p>El enlace expirará en ${PASSWORD_RESET_EXPIRATION_MINUTES} minutos.</p>
        <p><a href="${resetUrl.toString()}">Restablecer contraseña</a></p>
        <p>Si no solicitaste este cambio, puedes ignorar este correo.</p>
      `,
    });
  } catch (error: unknown) {
    // Invalidamos únicamente el token cuyo correo falló.
    try {
      await prisma.passwordReset.updateMany({
        where: { tokenHash, usedAt: null },
        data: { usedAt: new Date() },
      });
    } catch {
      // Conservamos el error original.
    }

    throw error;
  }
}

export async function confirmPasswordReset(
  prisma: PrismaClient,
  token: string,
  newPassword: string,
): Promise<boolean> {
  const tokenHash = hashToken(token);

  return prisma.$transaction(async (tx) => {
    const reset = await tx.passwordReset.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        userId: true,
        expiresAt: true,
        usedAt: true,
      },
    });

    if (!reset || reset.usedAt || reset.expiresAt <= new Date()) {
      return false;
    }

    const passwordHash = await hashPassword(newPassword);
    const now = new Date();

    // El token solo puede consumirse una vez.
    const consumed = await tx.passwordReset.updateMany({
      where: {
        id: reset.id,
        usedAt: null,
        expiresAt: { gt: now },
      },
      data: { usedAt: now },
    });

    if (consumed.count !== 1) {
      return false;
    }

    await tx.user.update({
      where: { id: reset.userId },
      data: { passwordHash },
    });

    // Revocamos todas las sesiones de la cuenta.
    await tx.session.updateMany({
      where: {
        userId: reset.userId,
        revokedAt: null,
      },
      data: { revokedAt: now },
    });

    // Revocamos también sus refresh tokens.
    await tx.refreshToken.updateMany({
      where: {
        session: { userId: reset.userId },
        revokedAt: null,
      },
      data: { revokedAt: now },
    });

    // Invalidamos otras solicitudes pendientes.
    await tx.passwordReset.updateMany({
      where: {
        userId: reset.userId,
        usedAt: null,
      },
      data: { usedAt: now },
    });

    return true;
  });
}
