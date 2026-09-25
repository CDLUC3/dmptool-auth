import type { ResultSetHeader } from "mysql2";
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import { queryTable } from '@dmptool/utils';
import type { Config, dbQueryResponse, PublicUser, User, UserRow } from '../types.js';

const passwordSpecialCharacters = /[`!@#$%^&*_+\-=?~\s]/;
const disallowedPasswordCharacters = /[(){}[\]|\\:;"'<>,./]/;
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// TODO: Update the @dmptool/utils package to support withTransaction and use it here to ensure that user
//  creation is atomic and that the user is not created if any of the subsequent steps fail.

const usersTable: string = process.env.DB_USERS_TABLE || 'users';
const userEmailsTable: string = process.env.DB_USER_EMAILS_TABLE || 'user_emails';
const templateCollaboratorsTable: string = process.env.DB_TEMPLATE_COLLABORATORS_TABLE || 'template_collaborators';
const projectCollaboratorsTable: string = process.env.DB_PROJECT_COLLABORATORS_TABLE || 'project_collaborators';

/**
 * Converts a User object to a PublicUser object by omitting the passwordHash field.
 *
 * @param user the User object to convert
 * @returns a PublicUser object with the same properties as the input User, except for passwordHash
 */
const publicUser = (user: User): PublicUser => ({
  id: user.id,
  email: user.email,
  givenName: user.givenName,
  surName: user.surName,
  role: user.role,
  affiliationId: user.affiliationId,
  languageId: user.languageId,
  tokenVersion: user.tokenVersion,
  ssoId: user.ssoId,
  acceptedTerms: user.acceptedTerms,
  failed_login_attempts: user.failed_login_attempts,
});

/**
 * Converts a database row to a User object.
 *
 * @param row The database row to convert.
 * @returns A User object.
 */
const toUser = (row: UserRow): User => ({
  id: String(row.id),
  email: row.email,
  passwordHash: row.password,
  givenName: row.givenName ?? '',
  surName: row.surName ?? '',
  role: row.role,
  affiliationId: row.affiliationId ?? '',
  languageId: row.languageId ?? 'en',
  tokenVersion: 0,
  ssoId: row.ssoId ?? undefined,
  acceptedTerms: true,
  failed_login_attempts: row.failed_login_attempts ?? 0,
});

/**
 * Validates a password based on the following criteria:
 * - Minimum length of 8 characters
 * - Contains at least one uppercase letter
 * - Contains at least one lowercase letter
 * - Contains at least one digit
 * - Contains at least one special character from the set: `!@#$%^&*_+-=?~`
 * - Does not contain any disallowed characters: `(){}[]|\\:;"'<>,./`
 *
 * @param password The password string to validate.
 * @returns True if the password meets all criteria, false otherwise.
 */
const isValidPassword = (password: string): boolean =>
  password.length >= 8
  && /[A-Z]/.test(password)
  && /[a-z]/.test(password)
  && /\d/.test(password)
  && passwordSpecialCharacters.test(password)
  && !disallowedPasswordCharacters.test(password);

/**
 * Normalizes an email address by trimming whitespace and converting to lowercase.
 *
 * @param email The email address to normalize.
 * @returns The normalized email address.
 */
const normalizeEmail = (email: string): string => email.trim().toLowerCase();

/**
 * Type guard to check if a value is either a string or null.
 *
 * @param value The value to check.
 * @returns True if the value is a string or null, false otherwise.
 */
const isNullableString = (value: unknown): value is string | null =>
  typeof value === 'string' || value === null;

/**
 * Type guard to check if a database row conforms to the UserRow interface.
 *
 * @param row The database row to check.
 * @returns True if the row is a UserRow, false otherwise.
 */
const isUserRow = (row: Record<string, unknown>): row is UserRow =>
  (typeof row.id === 'number' || typeof row.id === 'string')
  && typeof row.email === 'string'
  && typeof row.password === 'string'
  && typeof row.role === 'string'
  && isNullableString(row.givenName)
  && isNullableString(row.surName)
  && isNullableString(row.affiliationId)
  && isNullableString(row.languageId)
  && isNullableString(row.ssoId);

/**
 * Manages DMPTool user accounts stored in the `users` and `userEmails` tables.
 */
export class UserStore {
  constructor(private readonly config: Config) {}

  /**
   * Gets a peppered version of the password using the configured pepper secret.
   *
   * @param password - The password to pepper.
   * @returns The peppered password string.
   */
  private getPepperedPassword(password: string): string {
    return crypto
        .createHmac('sha256', this.config.pepperSecret)
        .update(password)
        .digest('hex');
  }

  /**
   * Hashes a password using bcrypt with the configured number of salt rounds.
   *
   * @param password - The password to hash.
   * @returns A Promise that resolves to the hashed password string.
   */
  private async hashPassword(password: string): Promise<string> {
    const peppered: string = this.getPepperedPassword(password);
    const salt: string = await bcrypt.genSalt(this.config.bcryptSaltRounds);
    return await bcrypt.hash(peppered, salt);
  }

  /**
   * Creates a new user account in the database with the provided input data.
   *
   * @param input - An object containing the user's email, password, and optional fields such as role,
   * givenName, surName, affiliationId, languageId, and ssoId.
   * @returns A Promise that resolves to a PublicUser object representing the newly created user or
   * undefined if the creation fails.
   */
  async create(
    input: Omit<User, 'id' | 'passwordHash' | 'tokenVersion'> & { password: string },
  ): Promise<PublicUser | undefined> {
    // Normalize and validate the email and password
    const email: string = normalizeEmail(input.email);
    if (!emailPattern.test(email)) throw new Error('Invalid email address');
    if (!isValidPassword(input.password)) throw new Error('Invalid password format');
    if (!input.acceptedTerms) throw new Error('Terms must be accepted');

    // Make sure the email is not already in use
    const existing: User | undefined = await this.findByEmail(email);
    if (existing) throw new Error('A user with this email already exists');

    // Hash the password using bcrypt
    const passwordHash: string = await this.hashPassword(input.password);

    const response: dbQueryResponse = await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `INSERT INTO ${usersTable}
        (password, role, givenName, surName, affiliationId, acceptedTerms, languageId, ssoId)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        passwordHash,
        'RESEARCHER',  // New users are always created with the RESEARCHER role
        this.capitalize(input.givenName),
        this.capitalize(input.surName),
        input.affiliationId?.trim(),
        true,   // They wouldn't have been able to create an account without accepting the terms
        input.languageId?.trim() || 'en-US',
        input.ssoId?.trim() ?? null,
      ],
    );
    if (!response.results || (response.results as ResultSetHeader).affectedRows === 0) {
      this.config.logger.error({ input }, 'Unable to create new user in the database');
      return undefined;
    }

    const userId: number | undefined = (response.results as ResultSetHeader).insertId;
    if (!userId) {
      this.config.logger.error({ input }, 'No id was assigned to new user in the database');
      return undefined;
    }

    // Backfill the createdById and modifiedById fields for the new user
    await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `UPDATE ${usersTable} SET createdById = ?, modifiedById = ? WHERE id = ?`,
      [userId, userId, userId],
    );

    // Add the primary email address for the new user in the userEmails table
    await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `INSERT INTO ${userEmailsTable} (userId, email, isPrimary, isConfirmed, createdById, modifiedById)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, email, true, false, userId, userId],
    );

    // Accept any open invitations to collaborate
    await this.claimOpenTemplateCollaborations(email, userId);
    await this.claimOpenProjectCollaborations(email, userId);

    const user: PublicUser | undefined = await this.findById(String(userId));
    if (!user) {
      this.config.logger.error({ input, userId: userId }, 'Unable to retrieve newly created user from the database');
      return undefined;
    }

    return user;
  }

  /**
   * Authenticates a user by their email and password.
   * If the email and password are valid, updates the user's last sign-in timestamp and returns
   * the public user object.
   * If the email or password are invalid, returns undefined.
   *
   * @param email The email address of the user to authenticate.
   * @param password The password of the user to authenticate.
   * @returns A Promise that resolves to the public user object if authentication is successful, or undefined if not.
   */
  async authenticate(email: string, password?: string): Promise<PublicUser | undefined> {
    // Validate the email and password are valid. If not, return undefined.
    if (!emailPattern.test(normalizeEmail(email)) || (password && !isValidPassword(password))) return undefined;

    const user: User | undefined = await this.findByEmail(email);
    if (!user) return undefined;

    // If a password was supplied, and it did not match the stored password, return undefined
    const passwordHash: string = this.getPepperedPassword(password || '');
    if ((password && !(await bcrypt.compare(passwordHash, user.passwordHash)))) {
      // Increment the failed login attempts for the user.
      if (user) {
        await queryTable(
            { ...this.config.database, logger: this.config.logger },
            `UPDATE ${usersTable} SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`,
            [user.id],
        );

        // If it has reached 5, lock the account.
        const newAttempts = (user.failed_login_attempts || 0) + 1;
        if (newAttempts >= 5) {
          await queryTable(
              { ...this.config.database, logger: this.config.logger },
              `UPDATE ${usersTable} SET locked = 1 WHERE id = ?`,
              [user.id],
          );
        }
      }
      return undefined;
    }

    // Update the last sign-in timestamp and method for the user
    await queryTable(
        { ...this.config.database, logger: this.config.logger },
        `UPDATE ${usersTable} SET failed_login_attempts = 0, last_sign_in = CURRENT_TIMESTAMP, last_sign_in_via = ? WHERE id = ?`,
        ['PASSWORD', user.id],
    );
    return user;
  }

  /**
   * Replace a user's password using the same validation and bcrypt settings as account creation.
   *
   * @param id The ID of the user whose password is to be reset.
   * @param password The new password to set for the user.
   * @returns A Promise that resolves to true if the password was successfully reset, or false otherwise.
   */
  async resetPassword(id: string, password: string): Promise<boolean> {
    if (!isValidPassword(password)) throw new Error('Invalid password format');

    const passwordHash: string = await this.hashPassword(password);
    const response: dbQueryResponse = await queryTable(
        { ...this.config.database, logger: this.config.logger },
        `UPDATE ${usersTable} SET password = ? WHERE id = ? AND active = 1 AND locked = 0`,
        [passwordHash, id],
    );
    return Boolean(response.results && !Array.isArray(response.results)
        && (response.results as ResultSetHeader).affectedRows > 0);
  }

  /**
   * Change a user's password after verifying their current password.
   *
   * @param id The ID of the authenticated user.
   * @param currentPassword The user's current password.
   * @param newPassword The replacement password.
   * @returns Whether the current password was valid and the update succeeded.
   */
  async changePassword(id: string, currentPassword: string, newPassword: string): Promise<boolean> {
    if (!isValidPassword(newPassword)) throw new Error('Invalid password format');

    const pepperedPassword: string = this.getPepperedPassword(currentPassword);
    const user: User | undefined = await this.findRaw(
        `SELECT u.id, u.password, u.role, u.givenName, u.surName, u.affiliationId, u.languageId, u.ssoId, ue.email, u.failedLoginAttempts
       FROM ${usersTable} u JOIN ${userEmailsTable} ue ON ue.userId = u.id AND ue.isPrimary = 1
       WHERE u.id = ? AND u.active = 1 AND u.locked = 0 LIMIT 1`,
        [id],
    );
    if (!user || !(await bcrypt.compare(pepperedPassword, user.passwordHash))) return false;

    return this.resetPassword(id, newPassword);
  }

  /**
   * Logs in a user via SSO.
   *
   * @param ssoId The SSO ID of the user to log in.
   * @returns A Promise that resolves to the public user object if login is successful, or undefined if not.
   */
  async ssoLogin(ssoId: string): Promise<PublicUser | undefined> {
    const user: PublicUser | undefined = await this.findBySsoId(ssoId);
    if (!user) return undefined;

    // Update the last sign-in timestamp and method for the user
    await queryTable(
        { ...this.config.database, logger: this.config.logger },
        `UPDATE ${usersTable} SET failed_login_attempts = 0, last_sign_in = CURRENT_TIMESTAMP, last_sign_in_via = ? WHERE id = ?`,
        ['SSO', user.id],
    );
    return user;
  }

  /**
   * Finds a user by their ID.
   *
   * @param id The ID of the user to find.
   * @returns The user if found, otherwise undefined.
   */
  async findById(id: string): Promise<PublicUser | undefined> {
    const user: User | undefined = await this.findRaw(
      `SELECT u.id, u.password, u.role, u.givenName, u.surName, u.affiliationId, u.languageId, u.ssoId, ue.email, u.failed_login_attempts
       FROM ${usersTable} u JOIN ${userEmailsTable} ue ON ue.userId = u.id AND ue.isPrimary = 1
       WHERE u.id = ? AND u.active = 1 AND u.locked = 0 LIMIT 1`,
      [id],
    );
    return user ? publicUser(user) : undefined;
  }

  /**
   * Finds a user by their email address.
   *
   * @param email The email address of the user to find.
   * @returns The user if found, otherwise undefined.
   */
  async findByEmail(email: string): Promise<User | undefined> {
    return this.findRaw(
      `SELECT u.id, u.password, u.role, u.givenName, u.surName, u.affiliationId, u.languageId, u.ssoId, ue.email, u.failed_login_attempts
       FROM ${usersTable} u JOIN ${userEmailsTable} ue ON ue.userId = u.id
       WHERE LOWER(ue.email) = ? AND (ue.isPrimary = 1 OR ue.isConfirmed = 1)
         AND u.active = 1 AND u.locked = 0 LIMIT 1`,
      [normalizeEmail(email)],
    );
  }

  /**
   * Finds a user by their SSO ID.
   *
   * @param ssoId The SSO ID of the user to find.
   * @returns The user if found, otherwise undefined.
   */
  async findBySsoId(ssoId: string): Promise<PublicUser | undefined> {
    const user: User | undefined = await this.findRaw(
      `SELECT u.id, u.password, u.role, u.givenName, u.surName, u.affiliationId, u.languageId, u.ssoId, ue.email, u.failed_login_attempts
       FROM ${usersTable} u JOIN ${userEmailsTable} ue ON ue.userId = u.id AND ue.isPrimary = 1 
       WHERE u.ssoId = ? AND u.active = 1 AND u.locked = 0 LIMIT 1`,
      [ssoId],
    );
    return user ? publicUser(user) : undefined;
  }

  /**
   * Helpers to find a user by executing a raw SQL query and returning the first matching user, if any.
   *
   * @param sql the SQL query to execute
   * @param values the values to use in the SQL query
   * @private
   */
  private async findRaw(sql: string, values: unknown[]): Promise<User | undefined> {
    const rows: dbQueryResponse = await queryTable(
      { ...this.config.database, logger: this.config.logger },
      sql,
      values
    );

    const results: unknown[] = Array.isArray(rows) ? rows : Array.isArray(rows.results) ? rows.results : [];
    if (results[0]) {
      const isUser: boolean = isUserRow(results[0] as UserRow);
      return isUser ? toUser(results[0] as UserRow) : undefined;
    }
    return undefined;
  }

  /**
   * Claims any open invitations to collaborate on a Template for the email
   *
   * @param email the email address of the user
   * @param userId the ID of the user
   * @private
   */
  private async claimOpenTemplateCollaborations(email: string, userId: number): Promise<void> {
    await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `UPDATE ${templateCollaboratorsTable} SET userId = ? WHERE email = ?`,
      [userId, email],
    );
  }

  /**
   * Claims any open invitations to collaborate on a Project for the email
   *
   * @param email the email address of the user
   * @param userId the ID of the user
   * @private
   */
  private async claimOpenProjectCollaborations(email: string, userId: number): Promise<void> {
    await queryTable(
      { ...this.config.database, logger: this.config.logger },
      `UPDATE ${projectCollaboratorsTable} SET userId = ? WHERE email = ?`,
      [userId, email],
    );
  }

  /**
   * Capitalizes the first letter of a string.
   *
   * @param str The string to capitalize.
   * @returns The capitalized string.
   * @private
   */
  private capitalize(str: string): string {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
}
