import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';

const queryTable = jest.fn<(config: unknown, sql: string, values?: unknown[]) => Promise<unknown>>();
jest.unstable_mockModule('@dmptool/utils', () => ({ queryTable }));
const { UserStore } = await import('../userStore.js');

const config = {
  database: {},
  bcryptSaltRounds: 4,
  pepperSecret: 'test-pepper-secret',
  maxFailedSignInAttempts: 5,
  logger: { error: jest.fn() },
};

const pepperPassword = (password: string): string => crypto
  .createHmac('sha256', config.pepperSecret)
  .update(password)
  .digest('hex');

beforeEach(() => {
  queryTable.mockReset();
});

describe('UserStore', () => {
  it.each([8, 12, 24])('generates a valid password of length %i', (length) => {
    const repository = new UserStore(config as never);
    const password = repository['generateRandomPassword'](length);

    expect(password).toHaveLength(length);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/\d/);
    expect(password).toMatch(/[!@#$%^&*_+\-=?~]/);
    expect(password).not.toMatch(/[(){}[\]|\\:;"'<>,./]/);
  });

  it.each([7, 8.5, NaN])('rejects invalid generated password length %s', (length) => {
    const repository = new UserStore(config as never);
    expect(() => repository['generateRandomPassword'](length)).toThrow(RangeError);
  });

  it('creates a normalized public user and claims its outstanding collaborations', async () => {
    queryTable
      .mockResolvedValueOnce({ results: [], fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1, insertId: 42 }, fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] })
      .mockResolvedValueOnce({ results: [{
        id: 42, email: 'alice@example.test', password: 'hash', role: 'RESEARCHER',
        givenName: 'Alice', surName: 'Example', affiliationId: 'affiliation-1', languageId: 'en-US',
        ssoId: null, locked: 0, failed_sign_in_attempts: 0,
      }], fields: [] });
    const repository = new UserStore(config as never);
    const user = await repository.create({
      email: ' ALICE@example.test ',
      password: 'Passw0rd!',
      givenName: 'Alice',
      surName: 'Example',
      affiliationId: ' affiliation-1 ',
      languageId: ' en-US ',
      role: 'RESEARCHER',
      acceptedTerms: true,
      remainingSignInAttempts: 5,
      locked: false,
    });

    expect(user).toMatchObject({ id: '42', email: 'alice@example.test', role: 'RESEARCHER' });
    expect(user).not.toHaveProperty('passwordHash');
    expect(queryTable.mock.calls[1][2]).toEqual([
      expect.any(String), 'RESEARCHER', 'Alice', 'Example', 'affiliation-1', true, 'en-US', null,
    ]);
    expect(queryTable.mock.calls[4][2]).toEqual([42, 'alice@example.test']);
    expect(queryTable.mock.calls[5][2]).toEqual([42, 'alice@example.test']);
  });

  it.each([
    ['invalid email', { email: 'not-an-email', password: 'Passw0rd!', acceptedTerms: true }, 'email', 'Invalid email format'],
    ['weak password', { email: 'user@example.test', password: 'password', acceptedTerms: true }, 'password', 'Invalid password format'],
    ['unaccepted terms', { email: 'user@example.test', password: 'Passw0rd!', acceptedTerms: false }, 'acceptedTerms', 'Terms must be accepted'],
  ])('rejects %s before querying the database', async (_, input, field, message) => {
    const repository = new UserStore(config as never);
    const resp = await repository.create({
      remainingSignInAttempts: 5, locked: false, givenName: 'User', surName: 'Example', affiliationId: '', languageId: 'en', role: 'RESEARCHER', ...input,
    });
    expect(resp).toEqual({"errors": {[field]: message}, "signupFailed": true});
    expect(queryTable).not.toHaveBeenCalled();
  });

  it.each([
    ['too short', 'Pw1!'],
    ['without uppercase', 'password1!'],
    ['without lowercase', 'PASSWORD1!'],
    ['without digit', 'Password!'],
    ['without special character', 'Password1'],
    ['with a disallowed character', 'Password1!('],
  ])('rejects a password that is %s', async (_, password) => {
    const repository = new UserStore(config as never);
    const resp = await repository.create({
      email: 'user@example.test', password, givenName: 'User', surName: 'Example',
      affiliationId: '', languageId: 'en', role: 'RESEARCHER', acceptedTerms: true,
      remainingSignInAttempts: 5, locked: false
    });
    expect(resp).toEqual({"errors": {"password": "Invalid password format"}, "signupFailed": true});
  });

  it('handles duplicate and database-failed user creation paths', async () => {
    const repository = new UserStore(config as never);
    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce({
      id: '1', email: 'user@example.test', passwordHash: 'hash', givenName: '', surName: '',
      role: 'RESEARCHER', affiliationId: '', languageId: 'en', tokenVersion: 0, acceptedTerms: true,
      remainingSignInAttempts: 5, locked: false
    });
    const resp = await repository.create({
      email: 'user@example.test', password: 'Passw0rd!', givenName: 'User', surName: 'Example',
      affiliationId: '', languageId: 'en', role: 'RESEARCHER', acceptedTerms: true,
      remainingSignInAttempts: 5, locked: false
    });
    expect(resp).toEqual({"errors": {"general": "A user with this email already exists"}, "signupFailed": true});

    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce(undefined);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] });
    const resp2 = await repository.create({
      email: 'user@example.test', password: 'Passw0rd!', givenName: 'User', surName: 'Example',
      affiliationId: '', languageId: 'en', role: 'RESEARCHER', acceptedTerms: true,
      remainingSignInAttempts: 5, locked: false
    });
    expect(resp2).toEqual({"errors": {"general": "Something went wrong while creating your account. Please try again later."}, "signupFailed": true});

    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce(undefined);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1, insertId: 0 }, fields: [] });
    const resp3 = await repository.create({
      email: 'user@example.test', password: 'Passw0rd!', givenName: '', surName: '',
      affiliationId: '', languageId: '', role: 'RESEARCHER', acceptedTerms: true,
      remainingSignInAttempts: 5, locked: false
    });
    expect(resp3).toEqual({"errors": {"general": "Unable to create your account. Please try again later."}, "signupFailed": true});
    expect(config.logger.error).toHaveBeenCalled();
  });

  it('creates a user through its successful SQL and collaboration paths', async () => {
    const repository = new UserStore(config as never);
    jest.spyOn(repository, 'findByEmail').mockResolvedValue(undefined);
    jest.spyOn(repository, 'findById').mockResolvedValue({
      id: '7', email: 'alice@example.test', givenName: '', surName: '', role: 'RESEARCHER',
      affiliationId: '', languageId: 'en-US', tokenVersion: 0, acceptedTerms: true,
      remainingSignInAttempts: 5, locked: false
    });
    queryTable
      .mockResolvedValueOnce({ results: { affectedRows: 1, insertId: 7 }, fields: [] })
      .mockResolvedValue({ results: { affectedRows: 1 }, fields: [] });

    const input = {
      email: ' ALICE@example.test ', password: 'Passw0rd!', givenName: '', surName: '',
      ssoId: ' sso-1 ',
      role: 'ADMIN', acceptedTerms: true,
    } as never;
    await expect(repository.create(input)).resolves.toMatchObject({ id: '7', email: 'alice@example.test' });
    const values = queryTable.mock.calls[0]![2] as unknown[];
    expect(values.slice(0, 7)).toEqual([
      expect.any(String), 'RESEARCHER', '', '', undefined, true, 'en-US',
    ]);
    await expect(bcrypt.compare(pepperPassword('sso-1'), values[7] as string)).resolves.toBe(true);
  });

  const row = {
    id: 1, email: 'user@example.test', password: 'hash', role: 'RESEARCHER',
    givenName: 'User', surName: 'Example', affiliationId: 'org', languageId: 'en', ssoId: 'sso-1',
    failed_sign_in_attempts: 0,
    locked: 0,
  };

  it('maps valid raw rows for all public lookup methods', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce([row]);
    await expect(repository.findById('1')).resolves.toMatchObject({ id: '1', email: row.email });
    queryTable.mockResolvedValueOnce([{ ...row, id: '2', givenName: null, surName: null, affiliationId: null, languageId: null, ssoId: null }]);
    await expect(repository.findByEmail(' USER@EXAMPLE.TEST ')).resolves.toMatchObject({
      id: '2', givenName: '', languageId: 'en', hasSSO: false,
    });
    queryTable.mockResolvedValueOnce([row]);
    await expect(repository.findBySsoId('sso-1')).resolves.toMatchObject({ id: '1', hasSSO: true });
    expect(queryTable.mock.calls[1]![2]).toEqual(['user@example.test']);
    await expect(bcrypt.compare(pepperPassword('sso-1'), queryTable.mock.calls[2]![2]![0] as string)).resolves.toBe(true);

    queryTable.mockResolvedValueOnce({ results: [], fields: [] });
    await expect(repository.findById('missing')).resolves.toBeUndefined();
  });

  it('migrates legacy plaintext SSO IDs after an encrypted lookup misses', async () => {
    const repository = new UserStore(config as never);
    queryTable
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([row])
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });

    await expect(repository.findBySsoId(' sso-1 ')).resolves.toMatchObject({ id: '1', hasSSO: true });
    await expect(bcrypt.compare(pepperPassword('sso-1'), queryTable.mock.calls[0]![2]![0] as string)).resolves.toBe(true);
    expect(queryTable.mock.calls[1]![2]).toEqual([' sso-1 ']);
    expect(queryTable.mock.calls[2]![1]).toContain('UPDATE users SET ssoId = ?');
    expect(queryTable.mock.calls[2]![2]?.[1]).toBe('1');
    await expect(bcrypt.compare(pepperPassword('sso-1'), queryTable.mock.calls[2]![2]![0] as string)).resolves.toBe(true);
  });

  it('returns undefined when no encrypted or legacy SSO ID matches', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce([]).mockResolvedValueOnce([]);

    await expect(repository.findBySsoId('sso-1')).resolves.toBeUndefined();
    expect(queryTable).toHaveBeenCalledTimes(2);
    await expect(bcrypt.compare(pepperPassword('sso-1'), queryTable.mock.calls[0]![2]![0] as string)).resolves.toBe(true);
    expect(queryTable.mock.calls[1]![2]).toEqual(['sso-1']);
  });

  it('reads SELECT rows from the queryTable response wrapper', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce({ results: [row], fields: [] });
    await expect(repository.findById('1')).resolves.toMatchObject({ id: '1' });
  });

  it('finds the SSO entity for an email domain', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce({
      results: [{
        affiliationId: 'https://ror.org/example',
        displayName: 'Example University',
        ssoEntityId: 'https://idp.example.test',
      }],
      fields: [],
    });

    await expect(repository.findSsoEntityIdByEmail('user@example.test')).resolves.toEqual({
      affiliationId: 'https://ror.org/example',
      displayName: 'Example University',
      ssoEntityId: 'https://idp.example.test',
    });
    expect(queryTable).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('FROM affiliationEmailDomains AS aed JOIN affiliations AS a'),
      ['example.test'],
    );
  });

  it.each([
    ['invalid email', 'invalid-email', undefined],
    ['missing SSO entity', 'user@example.test', { results: [], fields: [] }],
    ['unexpected query result', 'user@example.test', { results: { affectedRows: 0 }, fields: [] }],
  ])('returns undefined for a %s', async (_, email, queryResult) => {
    const repository = new UserStore(config as never);
    if (queryResult) queryTable.mockResolvedValueOnce(queryResult);

    await expect(repository.findSsoEntityIdByEmail(email)).resolves.toBeUndefined();
    if (queryResult) expect(queryTable).toHaveBeenCalledWith(expect.anything(), expect.any(String), ['example.test']);
    else expect(queryTable).not.toHaveBeenCalled();
  });

  it('finds the SSO entity for an entity ID', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce({
      results: [{
        affiliationId: 'https://ror.org/example',
        displayName: 'Example University',
        ssoEntityId: 'https://idp.example.test',
      }],
      fields: [],
    });

    await expect(repository.findSsoEntityIdById('https://idp.example.test')).resolves.toEqual({
      affiliationId: 'https://ror.org/example',
      displayName: 'Example University',
      ssoEntityId: 'https://idp.example.test',
    });
    expect(queryTable).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('FROM affiliations AS a WHERE a.ssoEntityId = ?'),
      ['https://idp.example.test'],
    );

    queryTable.mockResolvedValueOnce({ results: [], fields: [] });
    await expect(repository.findSsoEntityIdById('missing')).resolves.toBeUndefined();
  });

  it('finds the SSO entity for an affiliation URI', async () => {
    const repository = new UserStore(config as never);
    const entity = {
      affiliationId: 'https://ror.org/example',
      displayName: 'Example University',
      ssoEntityId: 'https://idp.example.test',
    };
    queryTable
      .mockResolvedValueOnce({ results: [entity], fields: [] })
      .mockResolvedValueOnce({ results: [], fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] });

    await expect(repository.findSsoEntityIdByURI(entity.affiliationId)).resolves.toEqual(entity);
    await expect(repository.findSsoEntityIdByURI('https://ror.org/missing')).resolves.toBeUndefined();
    await expect(repository.findSsoEntityIdByURI('https://ror.org/unexpected')).resolves.toBeUndefined();
    expect(queryTable).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('FROM affiliations AS a WHERE a.uri = ?'),
      [entity.affiliationId],
    );
  });

  it.each([
    [{ ...row, id: false }],
    [{ ...row, id: 1, email: 4 }],
    [{ ...row, password: null }],
    [{ ...row, role: null }],
    [{ ...row, givenName: 3 }],
    [{ ...row, surName: 3 }],
    [{ ...row, affiliationId: 3 }],
    [{ ...row, languageId: 3 }],
    [{ ...row, ssoId: 3 }],
    [{ ...row, failed_sign_in_attempts: '3' }],
    [[]],
  ])('returns undefined for malformed raw rows', async (rows) => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce(rows);
    await expect((repository as never as { findRaw: (sql: string, values: unknown[]) => Promise<unknown> })
      .findRaw('SELECT', [])).resolves.toBeUndefined();
  });

  it('authenticates valid passwords and resets failed login attempts', async () => {
    const repository = new UserStore(config as never);
    const user = {
      id: '1', email: row.email, passwordHash: await bcrypt.hash(pepperPassword('Passw0rd!'), 4), givenName: 'User',
      surName: 'Example', role: 'RESEARCHER', affiliationId: 'org', languageId: 'en',
      tokenVersion: 0, acceptedTerms: true, locked: false, remainingSignInAttempts: 5,
    };
    await expect(repository.authenticate('bad-email', 'Passw0rd!')).resolves.toMatchObject({ authenticationFailed: true });
    await expect(repository.authenticate(row.email)).resolves.toMatchObject({ authenticationFailed: true });
    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce(user);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    await expect(repository.authenticate(row.email, 'Passw0rd!')).resolves.toMatchObject({
      id: user.id,
      remainingSignInAttempts: 5,
    });
    expect(queryTable).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.stringContaining('failed_sign_in_attempts = 0'),
      ['PASSWORD', user.id],
    );
  });

  it('resets failed login attempts after incorrect passwords', async () => {
    const repository = new UserStore(config as never);
    const user = {
      id: '1', email: row.email, passwordHash: await bcrypt.hash(pepperPassword('Passw0rd!'), 4), givenName: 'User',
      surName: 'Example', role: 'RESEARCHER', affiliationId: 'org', languageId: 'en',
      tokenVersion: 0, acceptedTerms: true, locked: false, remainingSignInAttempts: 5,
    };
    const findByEmail = jest.spyOn(repository, 'findByEmail');
    findByEmail.mockResolvedValueOnce(user).mockResolvedValueOnce({ ...user, remainingSignInAttempts: 4 });
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });

    await expect(repository.authenticate(row.email, 'wrong')).resolves.toMatchObject({
      authenticationFailed: true,
      locked: false,
      remainingSignInAttempts: 4,
    });
    expect(queryTable).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('failed_sign_in_attempts = failed_sign_in_attempts + 1'),
      [user.id, 4],
    );

    findByEmail
      .mockResolvedValueOnce({ ...user, remainingSignInAttempts: 1 })
      .mockResolvedValueOnce({ ...user, locked: true, remainingSignInAttempts: 0 });
    queryTable
      .mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });

    await expect(repository.authenticate(row.email, 'Wrongpass1!')).resolves.toMatchObject({
      authenticationFailed: true,
      locked: true,
      remainingSignInAttempts: 0,
      wasJustLocked: true,
    });
    expect(queryTable).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.stringContaining('failed_sign_in_attempts = failed_sign_in_attempts + 1, locked = 1'),
      [user.id, 4],
    );

    findByEmail.mockResolvedValueOnce({ ...user, locked: true, remainingSignInAttempts: 0 });
    await expect(repository.authenticate(row.email, 'Passw0rd!')).resolves.toMatchObject({ locked: true });
    expect(queryTable).toHaveBeenCalledTimes(3);
  });

  it('does not clear a concurrent lockout after a failed password attempt', async () => {
    const repository = new UserStore(config as never);
    const staleUser = {
      id: '1', email: row.email, passwordHash: await bcrypt.hash(pepperPassword('Passw0rd!'), 4), givenName: 'User',
      surName: 'Example', role: 'RESEARCHER', affiliationId: 'org', languageId: 'en',
      tokenVersion: 0, acceptedTerms: true, locked: false, remainingSignInAttempts: 2,
    };
    jest.spyOn(repository, 'findByEmail')
      .mockResolvedValueOnce(staleUser)
      .mockResolvedValueOnce({ ...staleUser, locked: true, remainingSignInAttempts: 0 });
    queryTable
      .mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] });

    await expect(repository.authenticate(row.email, 'wrong')).resolves.toMatchObject({
      authenticationFailed: true,
      locked: true,
      wasJustLocked: false,
      remainingSignInAttempts: 0,
    });
    expect(queryTable).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.stringContaining('locked = 1'),
      [staleUser.id, 4],
    );
  });

  it('resets failed login attempts after a successful SSO login', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    await expect(repository.ssoLogin('1')).resolves.toBeUndefined();
    expect(queryTable).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.stringContaining('failed_sign_in_attempts = 0'),
      ['SSO', '1'],
    );
  });

  it('links a trusted SSO identity to an active user', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });

    await expect(repository.linkSsoId('1', 'mock:user@example.test')).resolves.toBeUndefined();
    expect(queryTable).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('UPDATE users SET ssoId = ?'),
      [expect.any(String), '1'],
    );
    await expect(bcrypt.compare(pepperPassword('mock:user@example.test'), queryTable.mock.calls[0]![2]![0] as string)).resolves.toBe(true);

    queryTable.mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] });
    await expect(repository.linkSsoId('missing', 'mock:missing@example.test'))
      .rejects.toThrow('Unable to link SSO identity for user missing');
  });

  it('validates and persists reset passwords', async () => {
    const repository = new UserStore(config as never);
    await expect(repository.resetPassword('1', 'password')).rejects.toThrow('Invalid password format');

    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    await expect(repository.resetPassword('1', 'Newpass1!')).resolves.toBe(true);
    expect(queryTable).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.stringContaining('UPDATE users SET password = ?'),
      [expect.any(String), '1'],
    );

    queryTable.mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] });
    await expect(repository.resetPassword('1', 'Newpass1!')).resolves.toBe(false);
  });
});
