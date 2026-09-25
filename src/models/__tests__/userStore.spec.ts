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
        givenName: 'Alice', surName: 'Example', affiliationId: 'affiliation-1', languageId: 'en-US', ssoId: null,
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
    ['invalid email', { email: 'not-an-email', password: 'Passw0rd!', acceptedTerms: true }, 'Invalid email address'],
    ['weak password', { email: 'user@example.test', password: 'password', acceptedTerms: true }, 'Invalid password format'],
    ['unaccepted terms', { email: 'user@example.test', password: 'Passw0rd!', acceptedTerms: false }, 'Terms must be accepted'],
  ])('rejects %s before querying the database', async (_, input, message) => {
    const repository = new UserStore(config as never);
    await expect(repository.create({
      givenName: 'User', surName: 'Example', affiliationId: '', languageId: 'en', role: 'RESEARCHER', ...input,
    })).rejects.toThrow(message);
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
    await expect(repository.create({
      email: 'user@example.test', password, givenName: 'User', surName: 'Example',
      affiliationId: '', languageId: 'en', role: 'RESEARCHER', acceptedTerms: true,
    })).rejects.toThrow('Invalid password format');
  });

  it('handles duplicate and database-failed user creation paths', async () => {
    const repository = new UserStore(config as never);
    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce({
      id: '1', email: 'user@example.test', passwordHash: 'hash', givenName: '', surName: '',
      role: 'RESEARCHER', affiliationId: '', languageId: 'en', tokenVersion: 0, acceptedTerms: true,
      failed_login_attempts: 0,
    });
    await expect(repository.create({
      email: 'user@example.test', password: 'Passw0rd!', givenName: 'User', surName: 'Example',
      affiliationId: '', languageId: 'en', role: 'RESEARCHER', acceptedTerms: true,
    })).rejects.toThrow('A user with this email already exists');

    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce(undefined);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 0 }, fields: [] });
    await expect(repository.create({
      email: 'user@example.test', password: 'Passw0rd!', givenName: 'User', surName: 'Example',
      affiliationId: '', languageId: 'en', role: 'RESEARCHER', acceptedTerms: true,
    })).resolves.toBeUndefined();

    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce(undefined);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1, insertId: 0 }, fields: [] });
    await expect(repository.create({
      email: 'user@example.test', password: 'Passw0rd!', givenName: '', surName: '',
      affiliationId: '', languageId: '', role: 'RESEARCHER', acceptedTerms: true,
    })).resolves.toBeUndefined();
    expect(config.logger.error).toHaveBeenCalled();
  });

  it('creates a user through its successful SQL and collaboration paths', async () => {
    const repository = new UserStore(config as never);
    jest.spyOn(repository, 'findByEmail').mockResolvedValue(undefined);
    jest.spyOn(repository, 'findById').mockResolvedValue({
      id: '7', email: 'alice@example.test', givenName: '', surName: '', role: 'RESEARCHER',
      affiliationId: '', languageId: 'en-US', tokenVersion: 0, acceptedTerms: true, failed_login_attempts: 0,
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
    expect(queryTable.mock.calls[0]![2]).toEqual([
      expect.any(String), 'RESEARCHER', '', '', undefined, true, 'en-US', 'sso-1',
    ]);
  });

  const row = {
    id: 1, email: 'user@example.test', password: 'hash', role: 'RESEARCHER',
    givenName: 'User', surName: 'Example', affiliationId: 'org', languageId: 'en', ssoId: 'sso-1',
    failed_login_attempts: 0,
  };

  it('maps valid raw rows for all public lookup methods', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce([row]);
    await expect(repository.findById('1')).resolves.toMatchObject({ id: '1', email: row.email });
    queryTable.mockResolvedValueOnce([{ ...row, id: '2', givenName: null, surName: null, affiliationId: null, languageId: null, ssoId: null }]);
    await expect(repository.findByEmail(' USER@EXAMPLE.TEST ')).resolves.toMatchObject({
      id: '2', givenName: '', languageId: 'en', ssoId: undefined,
    });
    queryTable.mockResolvedValueOnce([row]);
    await expect(repository.findBySsoId('sso-1')).resolves.toMatchObject({ id: '1' });
    expect(queryTable.mock.calls[1]![2]).toEqual(['user@example.test']);

    queryTable.mockResolvedValueOnce({ results: [], fields: [] });
    await expect(repository.findById('missing')).resolves.toBeUndefined();
  });

  it('reads SELECT rows from the queryTable response wrapper', async () => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce({ results: [row], fields: [] });
    await expect(repository.findById('1')).resolves.toMatchObject({ id: '1' });
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
    [{ ...row, failed_login_attempts: '3' }],
    [[]],
  ])('returns undefined for malformed raw rows', async (rows) => {
    const repository = new UserStore(config as never);
    queryTable.mockResolvedValueOnce(rows);
    await expect((repository as never as { findRaw: (sql: string, values: unknown[]) => Promise<unknown> })
      .findRaw('SELECT', [])).resolves.toBeUndefined();
  });

  it('authenticates passwords and resets failed login attempts after a successful password login', async () => {
    const repository = new UserStore(config as never);
    const user = {
      id: '1', email: row.email, passwordHash: await bcrypt.hash(pepperPassword('Passw0rd!'), 4), givenName: 'User',
      surName: 'Example', role: 'RESEARCHER', affiliationId: 'org', languageId: 'en',
      tokenVersion: 0, acceptedTerms: true, failed_login_attempts: 0,
    };
    await expect(repository.authenticate('bad-email', 'Passw0rd!')).resolves.toBeUndefined();
    await expect(repository.authenticate(row.email, 'password')).resolves.toBeUndefined();
    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce(undefined);
    await expect(repository.authenticate(row.email)).resolves.toBeUndefined();
    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce(user);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    await expect(repository.authenticate(row.email, 'Passw0rd!')).resolves.toEqual(user);
    expect(queryTable).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.stringContaining('failed_login_attempts = 0'),
      ['PASSWORD', user.id],
    );
  });

  it('increments failed login attempts and locks accounts after five failures', async () => {
    const repository = new UserStore(config as never);
    const user = {
      id: '1', email: row.email, passwordHash: await bcrypt.hash(pepperPassword('Passw0rd!'), 4), givenName: 'User',
      surName: 'Example', role: 'RESEARCHER', affiliationId: 'org', languageId: 'en',
      tokenVersion: 0, acceptedTerms: true, failed_login_attempts: 0,
    };
    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce(user);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });

    await expect(repository.authenticate(row.email, 'Wrongpass1!')).resolves.toBeUndefined();
    expect(queryTable).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('failed_login_attempts = failed_login_attempts + 1'),
      [user.id],
    );

    jest.spyOn(repository, 'findByEmail').mockResolvedValueOnce({ ...user, failed_login_attempts: 4 });
    queryTable
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] })
      .mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });

    await expect(repository.authenticate(row.email, 'Wrongpass1!')).resolves.toBeUndefined();
    expect(queryTable.mock.calls.slice(-2)).toEqual([
      [expect.anything(), expect.stringContaining('failed_login_attempts = failed_login_attempts + 1'), [user.id]],
      [expect.anything(), expect.stringContaining('SET locked = 1'), [user.id]],
    ]);
  });

  it('resets failed login attempts after a successful SSO login', async () => {
    const repository = new UserStore(config as never);
    const user = {
      id: '1', email: row.email, passwordHash: 'hash', givenName: 'User', surName: 'Example',
      role: 'RESEARCHER', affiliationId: 'org', languageId: 'en', tokenVersion: 0,
      acceptedTerms: true, failed_login_attempts: 3,
    };
    jest.spyOn(repository, 'findBySsoId').mockResolvedValueOnce(undefined);
    await expect(repository.ssoLogin('missing')).resolves.toBeUndefined();
    jest.spyOn(repository, 'findBySsoId').mockResolvedValueOnce(user);
    queryTable.mockResolvedValueOnce({ results: { affectedRows: 1 }, fields: [] });
    await expect(repository.ssoLogin('sso-1')).resolves.toMatchObject({ id: '1' });
    expect(queryTable).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.stringContaining('failed_login_attempts = 0'),
      ['SSO', user.id],
    );
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
