import { describe, expect, it } from '@jest/globals';
import { normalizeEmail } from '../utils.js';

describe('normalizeEmail', () => {
  it('trims surrounding whitespace and lowercases the address', () => {
    expect(normalizeEmail('  Jane.Doe@Example.COM \t')).toBe('jane.doe@example.com');
  });

  it('leaves an already normalized address unchanged', () => {
    expect(normalizeEmail('jane.doe@example.com')).toBe('jane.doe@example.com');
  });

  it('returns an empty string for a whitespace-only value', () => {
    expect(normalizeEmail('   ')).toBe('');
  });
});
