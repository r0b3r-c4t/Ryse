import { prisma } from '../lib/prisma.js';
import { generateSecureToken, hashToken } from '../lib/crypto.js';
import { sendEmail } from '../plugins/resend.js';

const TOKEN_EXPIRATION_MINUTES = 30;

interface RequestEmailVerificationParams {
    email: string;
}

export async function requestEmailVerification({
    email,
}: RequestEmailVerificationParams): Promise<void> {
    const user = await prisma.user.findUnique({
        where: { email },
        select: {
            id: true,
            emailVerifiedAt: true,
        },
    });

    // No revelamos si el correo existe o ya está verificado.
    if (!user || user.emailVerifiedAt) {
        return;
    }

    const token = generateSecureToken();
    const codeHash = hashToken(token);
    const expiresAt = new Date(
        Date.now() + TOKEN_EXPIRATION_MINUTES * 60 * 1000,
    );

    await prisma.$transaction(async (tx) => {
        await tx.emailVerification.updateMany({
            where: {
                userId: user.id,
                consumedAt: null,
                invalidatedAt: null,
            },
            data: {
                invalidatedAt: new Date(),
            },
        });

        await tx.emailVerification.create({
            data: {
                userId: user.id,
                codeHash,
                expiresAt,
            },
        });
    });

    const verificationUrl = new URL(
        '/verify-email',
        process.env.APP_URL ?? 'http://localhost:3000',
    );

    verificationUrl.searchParams.set('token', token);

    await sendEmail({
        to: email,
        subject: 'Verifica tu correo electrónico | RYSE',
        html: `
      <div style="font-family: Arial, sans-serif; max-width: 560px; margin: auto;">
        <h1>Verifica tu correo</h1>
        <p>Recibimos una solicitud para verificar tu correo electrónico en RYSE.</p>
        <p>
          <a href="${verificationUrl.toString()}"
             style="display: inline-block; padding: 12px 20px; background: #523dff; color: white; text-decoration: none; border-radius: 8px;">
            Verificar correo
          </a>
        </p>
        <p>Este enlace caduca en ${TOKEN_EXPIRATION_MINUTES} minutos.</p>
        <p>Si no solicitaste esta verificación, puedes ignorar este mensaje.</p>
      </div>
    `,
    });
}

export async function confirmEmailVerification(
    token: string,
): Promise<boolean> {
    const codeHash = hashToken(token);
    const now = new Date();

    return prisma.$transaction(async (tx) => {
        const verification = await tx.emailVerification.findFirst({
            where: {
                codeHash,
                consumedAt: null,
                invalidatedAt: null,
                expiresAt: {
                    gt: now,
                },
                user: {
                    emailVerifiedAt: null,
                },
            },
            select: {
                id: true,
                userId: true,
            },
        });

        if (!verification) {
            return false;
        }

        // Reclama el token solo si todavía está vigente y sin consumir.
        const consumed = await tx.emailVerification.updateMany({
            where: {
                id: verification.id,
                consumedAt: null,
                invalidatedAt: null,
                expiresAt: {
                    gt: now,
                },
            },
            data: {
                consumedAt: now,
            },
        });

        if (consumed.count !== 1) {
            return false;
        }

        await tx.user.update({
            where: {
                id: verification.userId,
                emailVerifiedAt: null,
            },
            data: {
                emailVerifiedAt: now,
            },
        });

        return true;
    });
}
