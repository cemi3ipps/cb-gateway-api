import crypto from "crypto"

const DEFAULT_KEY_LENGTH = 32 // bytes (256 bits)
const DEFAULT_IV_LENGTH = 6 // bytes
const MIN_IV_LENGTH = 6 // bytes
const MAX_IV_LENGTH = 16 // bytes
const ALGORITHM = "aes-256-gcm"
const DEFAULT_TAG_LENGTH = 16 // bytes

/**
 * Generates a cryptographically secure AES key.
 * @param length - Key length in bytes (default: 32 for AES-256)
 * @returns A Buffer containing the random key
 */
export function generateAesKey(length: number = DEFAULT_KEY_LENGTH): Buffer {
  if (length !== 32) {
    throw new Error("AES-256 requires a 32-byte (256-bit) key")
  }
  return crypto.randomBytes(length)
}

/**
 * Generates a cryptographically secure Initialization Vector (IV).
 * @param length - IV length in bytes (default: 16, recommended for GCM)
 * @returns A Buffer containing the random IV
 */
export function generateAesIv(
  length: number = DEFAULT_IV_LENGTH,
  isString: boolean = false,
): string | Buffer {
  if (length < MIN_IV_LENGTH || length > MAX_IV_LENGTH) {
    throw new Error(
      `IV length must be between ${MIN_IV_LENGTH} and ${MAX_IV_LENGTH} bytes for GCM mode`,
    )
  }
  return isString
    ? crypto.randomBytes(length).toString("hex").toUpperCase().slice(0, length)
    : crypto.randomBytes(length)
}

/**
 * Encrypts text using AES-256-GCM encryption.
 * @param text - The plaintext string to encrypt
 * @param key - The 32-byte AES key (use generateAesKey() to create)
 * @param iv - Optional IV; if not provided, a random one will be generated
 * @returns Object containing fullCiphertext, ciphertext, iv, and authTag (all as hex strings)
 * @throws Error if key length is invalid or encryption fails
 */
export function encrypt(text: string, key: Buffer, iv?: Buffer) {
  // Validate inputs
  if (!text) {
    throw new Error("Text to encrypt cannot be empty")
  }
  if (!key || key.length !== DEFAULT_KEY_LENGTH) {
    throw new Error("Key must be 32 bytes (256 bits) for AES-256")
  }

  try {
    // 1. Generate a random Initialization Vector (IV) if not provided
    if (!iv) {
      iv = crypto.randomBytes(DEFAULT_IV_LENGTH)
    } else if (iv.length < MIN_IV_LENGTH || iv.length > MAX_IV_LENGTH) {
      throw new Error(
        `IV length must be between ${MIN_IV_LENGTH} and ${MAX_IV_LENGTH} bytes for GCM mode`,
      )
    }

    // 2. Create cipher
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv)

    // 3. Encrypt the text
    let encrypted = cipher.update(text, "utf8", "hex")
    encrypted += cipher.final("hex")

    // 4. Get the Auth Tag (authentication tag for data integrity)
    const authTag = cipher.getAuthTag().toString("hex")

    // Return everything needed for decryption
    return {
      fullCiphertext: encrypted + authTag, // hex
      ciphertext: encrypted, // hex
      iv: iv.toString("hex"), // hex
      authTag: authTag, // hex
    }
  } catch (error) {
    throw new Error(
      `AES-256-GCM encryption failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

/**
 * Decrypts AES-256-GCM encrypted data.
 * @param encryptedData - Object containing ciphertext, iv, and authTag (all as hex strings)
 * @param key - The 32-byte AES key used for encryption
 * @returns The decrypted plaintext string
 * @throws Error if authentication fails (data tampered) or decryption fails
 */
export function decrypt(
  encryptedData: {
    ciphertext: Buffer
    iv: Buffer
    authTag: Buffer
  },
  key: Buffer,
): Buffer {
  // Validate inputs
  if (
    !encryptedData ||
    !encryptedData.ciphertext ||
    !encryptedData.iv ||
    !encryptedData.authTag
  ) {
    throw new Error("Encrypted data must contain ciphertext, iv, and authTag")
  }
  if (!key || key.length !== DEFAULT_KEY_LENGTH) {
    throw new Error("Key must be 32 bytes (256 bits) for AES-256")
  }

  const { ciphertext, iv, authTag } = encryptedData

  try {
    // 1. Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv)

    // 2. Set the auth tag before decrypting (for authenticity verification)
    decipher.setAuthTag(authTag)

    // 3. Decrypt
    let decrypted = decipher.update(ciphertext)
    decrypted = Buffer.concat([decrypted, decipher.final()]) // Will throw if auth tag is invalid

    return decrypted as Buffer
  } catch (error) {
    // Check if it's an authentication error
    if (
      error instanceof Error &&
      error.message.includes("Unsupported state or unable to authenticate data")
    ) {
      throw new Error("Authentication failed: Data may have been tampered with")
    }
    throw new Error(
      `AES-256-GCM decryption failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

export function decryptFullCiphertext(
  fullCiphertext: Buffer,
  iv: Buffer,
  key: Buffer,
  tagLength: number = DEFAULT_TAG_LENGTH,
): Buffer {
  // Validate inputs
  if (!fullCiphertext) {
    throw new Error("Full ciphertext cannot be empty")
  }
  if (!iv) {
    throw new Error("IV cannot be empty")
  }
  if (!key || key.length !== DEFAULT_KEY_LENGTH) {
    throw new Error("Key must be 32 bytes (256 bits) for AES-256")
  }

  if (fullCiphertext.length < tagLength) {
    throw new Error(
      `Full ciphertext is too short. Expected at least ${tagLength} hex characters for auth tag`,
    )
  }

  try {
    // Split the full ciphertext into ciphertext and auth tag
    // Auth tag is at the end
    const ciphertext = fullCiphertext.subarray(0, -tagLength)
    const authTag = fullCiphertext.subarray(-tagLength)

    // Use the existing decrypt function
    return decrypt(
      {
        ciphertext,
        iv,
        authTag,
      },
      key,
    )
  } catch (error) {
    throw new Error(
      `AES-256-GCM decryption with full ciphertext failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}
