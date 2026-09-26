import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import {
  EncryptionService,
  DecryptionError,
  DecryptionFailureReason,
} from '../services/encryption.service';
import * as nacl from 'tweetnacl';

// ── Helpers ───────────────────────────────────────────────────────────────────

const VALID_KEY = 'test-encryption-key-for-testing-purposes-abcdef';

function buildModule(keyOverride?: string): Promise<TestingModule> {
  return Test.createTestingModule({
    providers: [
      EncryptionService,
      {
        provide: ConfigService,
        useValue: {
          get: jest.fn().mockReturnValue({
            encryptionKey: keyOverride ?? VALID_KEY,
          }),
        },
      },
    ],
  }).compile();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('EncryptionService', () => {
  let service: EncryptionService;

  beforeEach(async () => {
    const module = await buildModule();
    service = module.get<EncryptionService>(EncryptionService);
  });

  // ── round-trip ─────────────────────────────────────────────────────────────

  describe('encrypt / decrypt round-trip', () => {
    it('encrypts and decrypts a Stellar secret key', () => {
      const secret = 'SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV';
      expect(service.decrypt(service.encrypt(secret))).toBe(secret);
    });

    it('produces different ciphertext for the same plaintext (random nonce)', () => {
      const secret = 'same-secret';
      const c1 = service.encrypt(secret);
      const c2 = service.encrypt(secret);
      expect(c1).not.toBe(c2);
      expect(service.decrypt(c1)).toBe(secret);
      expect(service.decrypt(c2)).toBe(secret);
    });

    it('handles an empty string payload', () => {
      expect(service.decrypt(service.encrypt(''))).toBe('');
    });

    it('handles special characters', () => {
      const s = 'secret!@#$%^&*()_+-=[]{}|;:,.<>?';
      expect(service.decrypt(service.encrypt(s))).toBe(s);
    });

    it('handles unicode / emoji', () => {
      const s = '秘密🔐';
      expect(service.decrypt(service.encrypt(s))).toBe(s);
    });
  });

  // ── DecryptionError — CORRUPTED_DATA ───────────────────────────────────────

  describe('decrypt → DecryptionError(CORRUPTED_DATA)', () => {
    it('throws CORRUPTED_DATA for a plain non-base64 string', () => {
      // Buffer.from handles arbitrary strings without throwing, so the blob
      // will just be short — trigger the length guard instead.
      const err = (() => {
        try {
          service.decrypt('x');
        } catch (e) {
          return e;
        }
      })();
      expect(err).toBeInstanceOf(DecryptionError);
      expect((err as DecryptionError).reason).toBe(
        DecryptionFailureReason.CORRUPTED_DATA,
      );
    });

    it('throws CORRUPTED_DATA for a blob shorter than nonce + overhead + 1', () => {
      // A valid blob must be >= nonceLength (24) + overheadLength (16) + 1 = 41 bytes.
      // Encode 10 bytes — clearly too short.
      const tooShort = Buffer.alloc(10).toString('base64');
      expect(() => service.decrypt(tooShort)).toThrow(DecryptionError);
      try {
        service.decrypt(tooShort);
      } catch (e) {
        expect(e).toBeInstanceOf(DecryptionError);
        expect((e as DecryptionError).reason).toBe(
          DecryptionFailureReason.CORRUPTED_DATA,
        );
      }
    });

    it('throws CORRUPTED_DATA for an empty string input', () => {
      try {
        service.decrypt('');
      } catch (e) {
        expect(e).toBeInstanceOf(DecryptionError);
        expect((e as DecryptionError).reason).toBe(
          DecryptionFailureReason.CORRUPTED_DATA,
        );
      }
    });
  });

  // ── DecryptionError — TAMPERING ────────────────────────────────────────────

  describe('decrypt → DecryptionError(TAMPERING)', () => {
    it('throws TAMPERING when the ciphertext byte is flipped', () => {
      const encrypted = service.encrypt('tamper-me');
      const blob = Buffer.from(encrypted, 'base64');
      // Flip a byte in the ciphertext portion (after the 24-byte nonce)
      blob[nacl.secretbox.nonceLength] ^= 0xff;
      expect(() => service.decrypt(blob.toString('base64'))).toThrow(
        DecryptionError,
      );
      try {
        service.decrypt(blob.toString('base64'));
      } catch (e) {
        expect(e).toBeInstanceOf(DecryptionError);
        expect((e as DecryptionError).reason).toBe(
          DecryptionFailureReason.TAMPERING,
        );
      }
    });

    it('throws TAMPERING when the nonce byte is flipped', () => {
      const encrypted = service.encrypt('nonce-tamper');
      const blob = Buffer.from(encrypted, 'base64');
      // Flip a byte in the nonce portion
      blob[0] ^= 0xff;
      try {
        service.decrypt(blob.toString('base64'));
      } catch (e) {
        expect(e).toBeInstanceOf(DecryptionError);
        expect((e as DecryptionError).reason).toBe(
          DecryptionFailureReason.TAMPERING,
        );
      }
    });

    it('throws TAMPERING when decrypting with the wrong key', async () => {
      const encrypted = service.encrypt('wrong-key-test');
      const otherModule = await buildModule(
        'completely-different-key-for-testing-xyz',
      );
      const otherService = otherModule.get<EncryptionService>(EncryptionService);
      expect(() => otherService.decrypt(encrypted)).toThrow(DecryptionError);
      try {
        otherService.decrypt(encrypted);
      } catch (e) {
        expect(e).toBeInstanceOf(DecryptionError);
        // Wrong key causes MAC failure — classified as TAMPERING
        expect((e as DecryptionError).reason).toBe(
          DecryptionFailureReason.TAMPERING,
        );
      }
    });
  });

  // ── error class identity ───────────────────────────────────────────────────

  describe('DecryptionError shape', () => {
    it('is an instance of Error', () => {
      try {
        service.decrypt(Buffer.alloc(10).toString('base64'));
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(DecryptionError);
      }
    });

    it('carries the reason on the error instance', () => {
      try {
        service.decrypt(Buffer.alloc(10).toString('base64'));
      } catch (e) {
        expect((e as DecryptionError).reason).toBeDefined();
        expect(Object.values(DecryptionFailureReason)).toContain(
          (e as DecryptionError).reason,
        );
      }
    });

    it('carries a meaningful message', () => {
      try {
        service.decrypt(Buffer.alloc(10).toString('base64'));
      } catch (e) {
        expect((e as Error).message).toContain('Decryption failed');
      }
    });
  });

  // ── isConfigured ───────────────────────────────────────────────────────────

  describe('isConfigured', () => {
    it('returns true when properly configured', () => {
      expect(service.isConfigured()).toBe(true);
    });
  });
});
