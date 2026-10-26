import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

const EMAIL_FROM = 'RYSE <onboarding@resend.dev>';

interface SendEmailParams {
    to: string;
    subject: string;
    html: string;
}

export async function sendEmail({
    to,
    subject,
    html,
}: SendEmailParams): Promise<void> {
    const { error } = await resend.emails.send({
        from: EMAIL_FROM,
        to,
        subject,
        html,
    });

    if (error) {
        throw new Error(`No se pudo enviar el correo: ${error.message}`);
    }
}
