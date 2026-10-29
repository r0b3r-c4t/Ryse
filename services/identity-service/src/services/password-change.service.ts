import type { PrismaClient } from '@prisma/client';

import { hashPassword, verifyPassword } from '../lib/crypto.js';

interface ChangePasswordParams {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

export async function changePassword(
  prisma: PrismaClient,
  { userId, currentPassword, newPassword }: ChangePasswordParams,
): Promise<'success' | 'invalid-current-password'> {
  return prisma.$transaction(async (tx) => {
    // Bloqueamos al usuario para serializar cambios de contraseña.
    const users = await tx.$queryRaw<{ id: string; passwordHash: string }[]>`
      SELECT id, "passwordHash"
      FROM "User"
      WHERE id = ${userId}
      FOR UPDATE
    `;

    const user = users[0];

    if (!user) {
      return 'invalid-current-password';
    }

    const isCurrentPasswordValid = await verifyPassword(user.passwordHash, currentPassword);

    if (!isCurrentPasswordValid) {
      return 'invalid-current-password';
    }

    const passwordHash = await hashPassword(newPassword);
    await tx.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    // Invalidamos los enlaces de recuperación que sigan pendientes.
    const now = new Date();
    await tx.passwordReset.updateMany({
      where: {
        userId,
        usedAt: null,
      },
      data: { usedAt: now },
    });

    return 'success';
  });
}
