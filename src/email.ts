import nodemailer, { type Mail, type SMTPSentMessageInfo } from "nodemailer";
import type { TransportOptions } from "nodemailer";
import type { Config } from "./types.js";

/**
 * Initializes the email transporter using the provided configuration.
 *
 * @param config the configuration object containing email settings
 * @returns a nodemailer transporter instance configured for AWS SES
 */
export const initializeEmailTransporter = (config: Config): Mail<SMTPSentMessageInfo> => {
  return nodemailer.createTransport({
    host: config.ses.endpoint,
    port: config.ses.port,
    secure: config.ses.port === 465,
    requireTLS: config.ses.port !== 465,
    auth: {
      user: config.ses.accessKey,
      pass: config.ses.accessSecret,
    },
  } as TransportOptions);
}

/**
 * Sends an email notification using the provided configuration and email details.
 * In development mode, the email is logged instead of sent to avoid accidental emails.
 *
 * @param config the configuration object containing email settings and logger
 * @param emailer the nodemailer transporter instance used to send emails
 * @param emailType the type of email being sent (e.g., "ResetPassword")
 * @param toAddresses the list of recipient email addresses
 * @param ccAddresses the list of CC email addresses (optional)
 * @param bccAddresses the list of BCC email addresses (optional)
 * @param subject the subject line of the email
 * @param message the body of the email message
 * @returns a Promise that resolves to true if the email was sent or logged successfully, false otherwise
 */
const sendEmail = async (
    config: Config,
    emailer: Mail<SMTPSentMessageInfo>,
    emailType: string,
    toAddresses: string[],
    ccAddresses: string[] = [],
    bccAddresses: string[] = [],
    subject: string,
    message: string,
): Promise<boolean> => {
    // Add the App name to the start of the subject line. We include the env when not in production
    const subjectLine = `${config.applicationName} - ${subject}`;

    if (['development'].includes(process.env.NODE_ENV || '')) {
        // When running in development mode, we do not have access to AWS SES and we probably don't want to
        // actually send emails to people by accident, so just log the message
        config.logger.info(
            { toAddresses, ccAddresses, bccAddresses, subjectLine, message },
            `Logging email notification of type '${emailType}' because we are in ${config.env} mode`
        );
        return true;

    } else {
        // Otherwise go ahead and send the email
        let response;
        const options = {
            from: `"${config.applicationName}" <${config.doNotReplyAddress}>`,
            sender: config.doNotReplyAddress,
            replyTo: config.helpDeskAddress,
            to: toAddresses.join(', '),
            cc: ccAddresses.join(', '),
            bcc: bccAddresses.join(', '),
            subject: subjectLine,
        };
        config.logger.debug(options, `Preparing to send ${emailType} email`);

        try {
            response = await emailer.sendMail({ ...options, html: message });
            const logInfo = { id: response?.messageId, to: toAddresses, subject: subject };
            config.logger.info(logInfo, `${emailType} email sent`);

            return true;
        } catch (err) {
            config.logger.error({ err, options }, `Unable to send ${emailType} email`);
        }
        return false;
    }
}

/**
 * Sends a reset password email to the user with a link to reset their password.
 *
 * @param config the configuration object containing email settings and logger
 * @param emailer the nodemailer transporter instance used to send emails
 * @param userEmail the email address of the user to send the reset password email to
 * @param resetToken the token to include in the reset password link
 * @returns a Promise that resolves to true if the email was sent successfully, false otherwise
 */
export const sendResetPasswordEmail = async (
    config: Config,
    emailer: Mail<SMTPSentMessageInfo>,
    userEmail: string,
    resetToken: string,
): Promise<boolean> => {
    if (!userEmail) {
        config.logger.error(
            { userId: userEmail },
            `User with ID ${userEmail} does not have an email address and cannot be sent a reset password email`
        );
        return false;
    }
    const resetPasswordUrl = `${config.domain}/login/reset-password?token=${resetToken}`;

    const message = `
<p>Hello ${userEmail},</p>
<p>Someone has requested a link to change your DMP Tool password. You can do this through the link below.</p>
<p><a href="${resetPasswordUrl}">Change my password</a></p>
<p>If you didn't request this, please ignore this email.</p>
<p>Your password won't change until you access the link above and create a new one.</p>
<p>All the best,<br>The DMP Tool team</p>
<p><small>Please do not reply to this email. If you have any questions or need help, please contact us at
<a href="mailto:${config.helpDeskAddress}">${config.helpDeskAddress}</a> or visit the <a href="${config.helpPageUrl}">Help Page</a>.</small></p>
`;

    return await sendEmail(
        config,
        emailer,
        'ResetPassword',
        [userEmail],
        [],
        [],
        'Reset Your Password',
        message
    );
}