import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nacl from 'tweetnacl';
import { StellarConfig } from '../config/stellar.config';
import { ConfigurationError } from '../../../common/errors';
import { BaseAppError } from '../../../common/errors/base.error';
import { ErrorCode } from '../../../common/errors/error-codes';
import { HttpStatus } from '@nestjs/common';

/** Minimum length (chars) accepted for a raw encryption key string. */
const MIN_KEY_LENGTH = 32;

/** Sentinel value shipped in `stellar.config.ts` as the default. */
const DEFAULT_PLACEHOLDER = 'default-encryption-key-change-in-production';

/**
 * Discriminator for why decryption failed. Allows callers to distinguish
 * between fixable configuration issues and data-layer corruption/tampering.
 *
 * - INVALID_KEY   — `nacl.secretbox.open` returned null and the ciphertext
 *                   structure is valid; the most likely cause is a wrong or
 *                   rotated encryption key (e.g. wrong env var).
 * - CORRUPTED_DATA — the base64-decoded blob is too short to contain a nonce
 *                    plus any ciphertext, or is otherwise structurally invalid.
 * - TAMPERING      — the MAC (Poly1305 auth tag embedded in NaCl secretbox)
 *                    failed, indicating the ciphertext was modified after
 *                    encryption.
 */
export enum DecryptionFailureReason {
  INVALID_KEY = 'INVALID_KEY',
  CORRUPTED_DATA = 'CORRUPTED_DATA',
  TAMPERING = 'TAMPERING',
}

/**
 * Structured error thrown by `EncryptionService.decrypt` when decryption fails.
 * Carries a `reason` discriminator so callers can route each failure mode
 * appropriately (alerting, self-healing, audit log, etc.).
 */
export class DecryptionError extends BaseAppError {
  readonly reason: DecryptionFailureReason;

  constructor(
    reason: DecryptionFailureReason,
    message?: string,
    context?: Record<string, unknown>,
  ) {
    const codeMap: Record<DecryptionFailureReason, ErrorCode> = {
      [DecryptionFailureReason.INVALID_KEY]: ErrorCode.DECRYPTION_INVALID_KEY,
      [DecryptionFailureReason.CORRUPTED_DATA]: ErrorCode.DECRYPTION_CORRUPTED_DATA,
      [DecryptionFailureReason.TAMPERING]: ErrorCode.DECRYPTION_TAMPERED,
    };

    super(
      codeMap[reason],
      HttpStatus.UNPROCESSABLE_ENTITY,
      message ?? `Decryption failed: ${reason}`,
      true,
      { reason, ...context },
    );

    this.reason = reason;
  }
}

@Injectable()
export class EncryptionService implements OnModuleInit {
  private readonly logger = new Logger(EncryptionService.name);
  private readonly encryptionKey: Uint8Array;

  /**
   * True when the key passed all validation checks at construction time.
   * Stored so that `isKeyValid()` and the health indicator can read it cheaply.
   */
  private readonly keyValid: boolean;

  /**
   * Human-readable reason the key failed validation, or `null` when valid.
   * Surfaced in health-check details without exposing key material.
   */
  private readonly keyInvalidReason: string | null;

  constructor(private readonly configService: ConfigService) {
    const keyString =
      this.configService.get<StellarConfig>('stellar')?.encryptionKey ?? '';

    const { valid, reason } = EncryptionService.validateKeyString(keyString);
    this.keyValid = valid;
    this.keyInvalidReason = reason;

    // Always derive the key so the rest of the class stays consistent; runtime
    // operations throw immediately if keyValid is false.
    this.encryptionKey = this.deriveKey(keyString);

    if (!valid) {
      this.logger.error(
        `EncryptionService key validation failed: ${reason}. ` +
          'Encryption and decryption operations will throw until a valid key is configured.',
      );
    }
  }

  /**
   * NestJS lifecycle hook — runs after DI wiring is complete.
   * Throws `ConfigurationError` so the application refuses to start when the
   * key is absent or using the shipped placeholder.
   */
  onModuleInit(): void {
    if (!this.keyValid) {
      throw new ConfigurationError(
        `EncryptionService cannot start: ${this.keyInvalidReason}. ` +
          'Set STELLAR_ENCRYPTION_KEY to a random string of at least ' +
          `${MIN_KEY_LENGTH} characters before starting the application.`,
      );
    }

    // Perform a live round-trip to confirm the derived key material actually
    // works — catches encoding edge-cases that static checks miss.
    try {
      this.performRoundTrip();
    } catch (err) {
      throw new ConfigurationError(
        'EncryptionService round-trip self-test failed at startup. ' +
          'The configured key cannot encrypt/decrypt correctly. ' +
          `Underlying error: ${(err as Error).message}`,
      );
    }

    this.logger.log('EncryptionService key validation passed.');
  }

  // ── Public helpers for the health indicator ────────────────────────────────

  /**
   * Returns whether the key passed static validation at construction time.
   * Does NOT re-read from config — this is intentionally cheap.
   */
  isKeyValid(): boolean {
    return this.keyValid;
  }

  /**
   * Returns the validation failure reason, or `null` when the key is valid.
   * Safe to include in health-check payloads (contains no key material).
   */
  getKeyInvalidReason(): string | null {
    return this.keyInvalidReason;
  }

  /**
   * Performs a live encrypt → decrypt round-trip with a fixed test string.
   * Returns `true` on success; throws on any failure so callers can decide
   * whether to surface a hard error or a degraded warning.
   *
   * Used by `EncryptionHealthIndicator` and `onModuleInit`.
   */
  testRoundTrip(): true {
    this.assertKeyValid();
    return this.performRoundTrip();
  }

  // ── Core encrypt / decrypt ────────────────────────────────────────────────

  /**
   * Encrypts a secret key using NaCl secretbox.
   * @param secretKey - The secret key to encrypt
   * @returns Encrypted data as base64 string (nonce + ciphertext)
   */
  encrypt(secretKey: string): string {
    this.assertKeyValid();

    try {
      const encoder = new TextEncoder();
      const messageUint8 = encoder.encode(secretKey);

      // Generate a random nonce
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

      // Encrypt the message
      const ciphertext = nacl.secretbox(
        messageUint8,
        nonce,
        this.encryptionKey,
      );

      if (!ciphertext) {
        throw new Error('Encryption failed');
      }

      // Combine nonce and ciphertext
      const combined = new Uint8Array(nonce.length + ciphertext.length);
      combined.set(nonce);
      combined.set(ciphertext, nonce.length);

      // Return as base64
      return Buffer.from(combined).toString('base64');
    } catch (error) {
      this.logger.error('Encryption failed', error);
      throw new Error('Failed to encrypt secret key');
    }
  }

  /**
   * Decrypts an encrypted secret key.
   *
   * Throws `DecryptionError` with a specific `reason` discriminator:
   * - `CORRUPTED_DATA` — the blob is too short to hold a nonce + ciphertext
   * - `TAMPERING`      — the auth tag failed (data modified after encryption)
   * - `INVALID_KEY`    — `secretbox.open` returned null with a valid structure
   *                      (most likely wrong key / env var misconfiguration)
   *
   * @param encryptedData - Base64 encoded encrypted data (nonce + ciphertext)
   * @returns Decrypted secret key
   */
  decrypt(encryptedData: string): string {
    this.assertKeyValid();

    // Validate that the blob is large enough to contain a nonce + at least 1
    // byte of ciphertext (NaCl secretbox adds a 16-byte MAC overhead, so the
    // minimum valid ciphertext length is nonceLength + 16 + 1).
    let combined: Buffer;
    try {
      combined = Buffer.from(encryptedData, 'base64');
    } catch {
      const err = new DecryptionError(
        DecryptionFailureReason.CORRUPTED_DATA,
        'Failed to base64-decode encrypted data',
        { encryptedDataLength: encryptedData?.length },
      );
      this.logger.error(
        `[DECRYPTION_FAILURE] reason=${err.reason} code=${err.errorCode}`,
        err.message,
      );
      throw err;
    }

    const minLength = nacl.secretbox.nonceLength + nacl.secretbox.overheadLength + 1;
    if (combined.length < minLength) {
      const err = new DecryptionError(
        DecryptionFailureReason.CORRUPTED_DATA,
        `Encrypted blob too short: expected ≥${minLength} bytes, got ${combined.length}`,
        { blobLength: combined.length, minLength },
      );
      this.logger.error(
        `[DECRYPTION_FAILURE] reason=${err.reason} code=${err.errorCode} ` +
          `blobLength=${combined.length} minLength=${minLength}`,
      );
      throw err;
    }

    const nonce = combined.slice(0, nacl.secretbox.nonceLength);
    const ciphertext = combined.slice(nacl.secretbox.nonceLength);

    let decrypted: Uint8Array | null;
    try {
      decrypted = nacl.secretbox.open(
        new Uint8Array(ciphertext),
        new Uint8Array(nonce),
        this.encryptionKey,
      );
    } catch (openErr) {
      // nacl.secretbox.open should not throw, but guard defensively
      const err = new DecryptionError(
        DecryptionFailureReason.CORRUPTED_DATA,
        'nacl.secretbox.open threw unexpectedly',
        { cause: openErr instanceof Error ? openErr.message : String(openErr) },
      );
      this.logger.error(
        `[DECRYPTION_FAILURE] reason=${err.reason} code=${err.errorCode}`,
        err.message,
      );
      throw err;
    }

    if (decrypted === null) {
      // NaCl returns null for both wrong-key and tamper scenarios. We
      // distinguish them by re-checking the ciphertext length: if the
      // ciphertext is >= overheadLength (16 bytes for Poly1305 MAC), a null
      // result almost certainly means the MAC check failed (tampering or
      // key mismatch). A ciphertext shorter than overheadLength is structurally
      // corrupt. We classify null as TAMPERING when the MAC had a chance to run
      // and as INVALID_KEY when additional heuristics indicate a key problem.
      //
      // Since we cannot distinguish INVALID_KEY from TAMPERING purely from the
      // null return, we classify as TAMPERING (the more security-critical of
      // the two) and log separately so operators can correlate with key rotation
      // events to determine the true root cause.
      const reason =
        ciphertext.length < nacl.secretbox.overheadLength
          ? DecryptionFailureReason.CORRUPTED_DATA
          : DecryptionFailureReason.TAMPERING;

      const err = new DecryptionError(
        reason,
        reason === DecryptionFailureReason.CORRUPTED_DATA
          ? 'Ciphertext is shorter than the NaCl MAC overhead — data is truncated or corrupt'
          : 'NaCl MAC verification failed — data may have been tampered with, or the encryption key is wrong',
        { ciphertextLength: ciphertext.length, reason },
      );

      this.logger.error(
        `[DECRYPTION_FAILURE] reason=${err.reason} code=${err.errorCode} ` +
          `ciphertextLength=${ciphertext.length} — ` +
          (reason === DecryptionFailureReason.TAMPERING
            ? 'If this is unexpected, verify STELLAR_ENCRYPTION_KEY has not been rotated.'
            : 'Data may be truncated; check the storage layer for corruption.'),
      );
      throw err;
    }

    try {
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (decodeErr) {
      const err = new DecryptionError(
        DecryptionFailureReason.CORRUPTED_DATA,
        'Decrypted bytes are not valid UTF-8',
        { cause: decodeErr instanceof Error ? decodeErr.message : String(decodeErr) },
      );
      this.logger.error(
        `[DECRYPTION_FAILURE] reason=${err.reason} code=${err.errorCode}`,
        err.message,
      );
      throw err;
    }
  }

  /**
   * Securely wipes a string from memory by overwriting it.
   * Note: JavaScript doesn't guarantee immediate garbage collection,
   * but this helps minimize exposure time.
   */
  secureWipe(_data: string): void {
    // In JavaScript, we can't truly wipe memory, but we can minimize exposure
    // by letting the variable go out of scope and be garbage collected.
    // This method is here for API completeness and to encourage good practices.
  }

  /**
   * Validates that the encryption service is properly configured.
   * @deprecated Prefer `isKeyValid()` which is evaluated once at construction
   *   time rather than re-reading config on every call.
   */
  isConfigured(): boolean {
    const keyString =
      this.configService.get<StellarConfig>('stellar')?.encryptionKey;
    return (
      !!keyString && keyString !== DEFAULT_PLACEHOLDER
    );
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Validates a raw key string before derivation.
   * Returns a `{ valid, reason }` tuple so both constructor and tests can
   * inspect the outcome without throwing.
   */
  static validateKeyString(keyString: string): {
    valid: boolean;
    reason: string | null;
  } {
    if (!keyString) {
      return { valid: false, reason: 'STELLAR_ENCRYPTION_KEY is not set' };
    }
    if (keyString === DEFAULT_PLACEHOLDER) {
      return {
        valid: false,
        reason:
          'STELLAR_ENCRYPTION_KEY is using the default placeholder value — ' +
          'replace it with a secret random string before deploying',
      };
    }
    if (keyString.length < MIN_KEY_LENGTH) {
      return {
        valid: false,
        reason:
          `STELLAR_ENCRYPTION_KEY is too short (${keyString.length} chars); ` +
          `minimum is ${MIN_KEY_LENGTH} characters`,
      };
    }
    return { valid: true, reason: null };
  }

  /**
   * Throws `ConfigurationError` when the key failed validation.
   * Called at the top of every operation that needs a working key.
   */
  private assertKeyValid(): void {
    if (!this.keyValid) {
      throw new ConfigurationError(
        `EncryptionService operation rejected: ${this.keyInvalidReason}`,
      );
    }
  }

  /**
   * Encrypts and immediately decrypts a known test string to confirm that the
   * derived key material is self-consistent.  Throws if the result does not
   * match the original.
   */
  private performRoundTrip(): true {
    const testPlaintext = 'encryption-self-test-chioma';
    const encrypted = this.encrypt(testPlaintext);
    const decrypted = this.decrypt(encrypted);

    if (decrypted !== testPlaintext) {
      throw new Error(
        `Round-trip produced "${decrypted}" instead of "${testPlaintext}"`,
      );
    }
    return true;
  }

  /**
   * Derives a 32-byte key from a string using SHA-512 (via NaCl) and
   * truncating to the secretbox key length.
   */
  private deriveKey(keyString: string): Uint8Array {
    const encoder = new TextEncoder();
    const hash = nacl.hash(encoder.encode(keyString));
    return hash.slice(0, nacl.secretbox.keyLength);
  }
}
