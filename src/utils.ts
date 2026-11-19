/**
 * Normalizes an email address by trimming whitespace and converting to lowercase.
 *
 * @param email The email address to normalize.
 * @returns The normalized email address.
 */
export const normalizeEmail = (email: string): string => email.trim().toLowerCase();
