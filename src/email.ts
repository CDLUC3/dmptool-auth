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
  const resetPasswordUrl = `${appBaseUrl(config)}/login/reset-password?token=${encodeURIComponent(resetToken)}`;

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

/**
 * Sends an account locked email to the user.
 *
 * @param config the configuration object containing email settings and logger
 * @param emailer the nodemailer transporter instance used to send emails
 * @param userEmail the email address of the user to send the account locked email to
 * @returns a Promise that resolves to true if the email was sent successfully, false otherwise
 */
export const sendAccountLockedEmail = async (
  config: Config,
  emailer: Mail<SMTPSentMessageInfo>,
  userEmail: string,
): Promise<boolean> => {
  if (!userEmail) {
    config.logger.error(
      { userId: userEmail },
      `User with ID ${userEmail} does not have an email address and cannot be sent an account locked email`
    );
    return false;
  }

  const message = `
<p>Hello ${userEmail},</p>
<p>Your account has been locked due to too many failed login attempts.</p>
<p>Please contact us at <a href="mailto:${config.helpDeskAddress}">${config.helpDeskAddress}</a> to regain access to your account.<br>The DMP Tool team</p>
`;

  return await sendEmail(
    config,
    emailer,
    'AccountLocked',
    [userEmail],
    [],
    [],
    'Your account has been locked',
    message
  );
}

/**
 * Escape a value so that it can be safely included in the HTML body of an email.
 *
 * @param value the value to escape
 * @returns the escaped value
 */
const escapeHtml = (value: string): string => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#39;');

/**
 * Return the base URL of the UI. DOMAIN usually includes the protocol already (e.g. http://localhost:3000),
 * so a protocol is only added when it is missing.
 *
 * @param config the configuration object containing the domain
 * @returns the base URL without a trailing slash
 */
const appBaseUrl = (config: Config): string => {
  if (/^https?:\/\//i.test(config.domain)) return config.domain.replace(/\/+$/, '');

  const protocol = ['development', 'test'].includes(config.env) ? 'http://' : 'https://';
  return `${protocol}${config.domain.replace(/\/+$/, '')}`;
};

/**
 * Sends an email asking the user to confirm that they own an email address they added to their account.
 *
 * @param config the configuration object containing email settings and logger
 * @param emailer the nodemailer transporter instance used to send emails
 * @param userId the ID of the user who added the email address (only used for logging, so it isn't in the link)
 * @param email the email address to confirm (the email is sent to this address)
 * @param confirmationToken the token to include in the confirmation link
 * @returns a Promise that resolves to true if the email was sent successfully, false otherwise
 */
export const sendEmailConfirmationEmail = async (
  config: Config,
  emailer: Mail<SMTPSentMessageInfo>,
  userId: string,
  email: string,
  confirmationToken: string,
): Promise<boolean> => {
  if (!email) {
    config.logger.error({ userId }, 'No email address was provided, so no email confirmation email was sent');
    return false;
  }
  const confirmUrl = `${appBaseUrl(config)}/email/confirm-email/${encodeURIComponent(confirmationToken)}`;
  const hours: number = Math.max(1, Math.round(config.ttl.emailConfirmation / 3600));

  const message = `
<p>Hello,</p>
<p>${escapeHtml(email)} was added to a DMP Tool account. To confirm that this is your email address, open the link below.</p>
<p><a href="${confirmUrl}">Confirm my email address</a></p>
<p>If you're asked to sign in, use the email address you normally sign in with, not this one.</p>
<p>This link expires in ${hours} ${hours === 1 ? 'hour' : 'hours'} and can only be used once.</p>
<p>If you didn't add this email address, you can ignore this email. It won't be confirmed unless you open the link above.</p>
<p>All the best,<br>The DMP Tool team</p>
<p><small>Please do not reply to this email. If you have any questions or need help, please contact us at
<a href="mailto:${config.helpDeskAddress}">${config.helpDeskAddress}</a> or visit the <a href="${config.helpPageUrl}">Help Page</a>.</small></p>
`;

  return await sendEmail(
    config,
    emailer,
    'EmailConfirmation',
    [email],
    [],
    [],
    'Please confirm your email address',
    message
  );
}
