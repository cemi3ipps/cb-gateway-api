import { describe, expect, it } from "bun:test"

import {
  convertToPem,
  deriveRsaPublicKey,
  getCbRequestId,
  getTraditionalRequestId,
  isValidPEM,
} from "./util"

describe("deriveRsaPublicKey", () => {
  const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgF2Gn+IS9WA5b9yW4TUUODQbXLWDtmp6yi/47YKE4aFbd8imJNxP
x6X8mLjQ0N5AoKuyUtHm5Waqlkd1Kf6NAS08Dra5gSjh9KYWRUnHmvJ8cMMpqf2V
TJJVXCtZIy9khAAcpueg/BefT3ri+9DDCMJf1WKic7cTN+BT2jivsyY9AgMBAAEC
gYBFaOozoBpXZYktTxSoje8ATOZLGAtDjwmK/NVYLkI9vGJzmUp17weemo7FasP4
jkIv6tIoUZIi1ateMQgPkJo0D8fT56xA3zl1ZNoGPvGD4BuWpYt8nONW/gXbQDRG
73XllVkBvKnmPM+uqcBRbDGdMBwpqWoZtox/pdftoesNSQJBAKXzZ5iKRzT3m7Dy
gCrxGz8+i/A7eUK6B3V6fB4tT0dv6EPJcw3agjp/W0m5vfC6jESVyXPNnsVGRchd
f80VkxcCQQCQRoM1DG/9Vl4KKjDM823QzheDBgRbf9ZKoP2s4icg38/TvET0FZ7V
IkGCICvUkubSBxzv7oNWR6NFDhFaUnXLAkAfT25TVHuc3b7NQuO1tmnqo9VpTP9S
/KBdpO94DhpwIwgSihagHYMGoHLL1TSmD7xZUF2C8N+s3tZZuHJdcl2fAkBkCH/w
yC7d+IQ7iAVOFXqOzFaBAisDRh/OntFEjYmTwZrXtDIbCuKV5KqHDsdVHIXuGgB2
W2m06PbLanWdqo8BAkEApKCGlDXowawUbxmIKte/QQ+N0moV5RL/87Z56W6pwyZe
BamXYYG8TMUa5okmIl1J0yVeFYr8vn+DoZd9MDA1fQ==
-----END RSA PRIVATE KEY-----`

  const expectedPublicKey = `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgF2Gn+IS9WA5b9yW4TUUODQbXLWD
tmp6yi/47YKE4aFbd8imJNxPx6X8mLjQ0N5AoKuyUtHm5Waqlkd1Kf6NAS08Dra5
gSjh9KYWRUnHmvJ8cMMpqf2VTJJVXCtZIy9khAAcpueg/BefT3ri+9DDCMJf1WKi
c7cTN+BT2jivsyY9AgMBAAE=
-----END PUBLIC KEY-----`

  it("should derive public key from private key", () => {
    const derivedPublicKey = deriveRsaPublicKey(testPrivateKey)
    // Trim to handle trailing newline differences
    expect(derivedPublicKey.trim()).toBe(expectedPublicKey.trim())
  })

  it("should return valid PEM format", () => {
    const derivedPublicKey = deriveRsaPublicKey(testPrivateKey)
    expect(isValidPEM(derivedPublicKey)).toBe(true)
  })

  it("should return public key with correct header", () => {
    const derivedPublicKey = deriveRsaPublicKey(testPrivateKey)
    expect(derivedPublicKey).toContain("-----BEGIN PUBLIC KEY-----")
    expect(derivedPublicKey).toContain("-----END PUBLIC KEY-----")
  })

  it("should throw error for invalid PEM format", () => {
    expect(() => {
      deriveRsaPublicKey("invalid_key")
    }).toThrow("Invalid PEM format for private key")
  })

  it("should throw error for empty string", () => {
    expect(() => {
      deriveRsaPublicKey("")
    }).toThrow("Invalid PEM format for private key")
  })

  it("should throw error for null input", () => {
    expect(() => {
      deriveRsaPublicKey(null as any)
    }).toThrow("Invalid PEM format for private key")
  })

  it("should throw error for public key instead of private key", () => {
    expect(() => {
      deriveRsaPublicKey(expectedPublicKey)
    }).toThrow("Failed to derive public key from private key")
  })

  it("should throw error for malformed private key", () => {
    const malformedKey = `-----BEGIN RSA PRIVATE KEY-----
INVALID_BASE64_DATA_HERE
-----END RSA PRIVATE KEY-----`
    expect(() => {
      deriveRsaPublicKey(malformedKey)
    }).toThrow("Failed to derive public key from private key")
  })
})

describe("isValidPEM", () => {
  it("should return true for valid public key PEM", () => {
    const validPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8sC1...
-----END PUBLIC KEY-----`
    expect(isValidPEM(validPublicKey)).toBe(true)
  })

  it("should return true for valid private key PEM", () => {
    const validPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC8sC1...
-----END RSA PRIVATE KEY-----`
    expect(isValidPEM(validPrivateKey)).toBe(true)
  })

  it("should return true for certificate PEM", () => {
    const validCert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL...
-----END CERTIFICATE-----`
    expect(isValidPEM(validCert)).toBe(true)
  })

  it("should return false for invalid PEM - missing BEGIN", () => {
    const invalidPem = `-----END PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8sC1...`
    expect(isValidPEM(invalidPem)).toBe(false)
  })

  it("should return false for invalid PEM - missing END", () => {
    const invalidPem = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8sC1...`
    expect(isValidPEM(invalidPem)).toBe(false)
  })

  it("should return false for mismatched labels", () => {
    const invalidPem = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8sC1...
-----END PRIVATE KEY-----`
    expect(isValidPEM(invalidPem)).toBe(false)
  })

  it("should return false for empty string", () => {
    expect(isValidPEM("")).toBe(false)
  })

  it("should return false for null", () => {
    expect(isValidPEM(null as any)).toBe(false)
  })

  it("should return false for undefined", () => {
    expect(isValidPEM(undefined as any)).toBe(false)
  })

  it("should return true for PEM with whitespace", () => {
    const validPem = `  -----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8sC1...
-----END PUBLIC KEY-----  `
    expect(isValidPEM(validPem)).toBe(true)
  })
})

describe("getTraditionalRequestId", () => {
  it("should return a string of default length (6)", () => {
    const reqId = getTraditionalRequestId()
    expect(reqId).toHaveLength(6)
  })

  it("should return uppercase by default", () => {
    const reqId = getTraditionalRequestId()
    expect(reqId).toBe(reqId.toUpperCase())
  })

  it("should return lowercase when isUpper is false", () => {
    const reqId = getTraditionalRequestId(6, false)
    expect(reqId).toBe(reqId.toLowerCase())
  })

  it("should return specified length", () => {
    const reqId = getTraditionalRequestId(10)
    expect(reqId).toHaveLength(10)
  })

  it("should return different values on multiple calls", () => {
    const reqId1 = getTraditionalRequestId()
    const reqId2 = getTraditionalRequestId()
    expect(reqId1).not.toBe(reqId2)
  })
})

describe("getCbRequestId", () => {
  it("should return a string of default length (6)", () => {
    const reqId = getCbRequestId()
    expect(reqId).toHaveLength(6)
  })

  it("should not contain special characters (-, _, /)", () => {
    const reqId = getCbRequestId()
    expect(reqId).not.toMatch(/[-_\/]/)
  })

  it("should return different values on multiple calls", () => {
    const reqId1 = getCbRequestId()
    const reqId2 = getCbRequestId()
    expect(reqId1).not.toBe(reqId2)
  })
})

describe("convertToPem", () => {
  it("should convert base64 to PUBLIC_KEY PEM format", () => {
    const base64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8sC1"
    const pem = convertToPem(base64, "PUBLIC_KEY")
    expect(pem).toContain("-----BEGIN PUBLIC KEY-----")
    expect(pem).toContain("-----END PUBLIC KEY-----")
    expect(pem).toContain(base64)
  })

  it("should convert base64 to PRIVATE_KEY PEM format", () => {
    const base64 = "MIICXQIBAAKBgQC8sC1"
    const pem = convertToPem(base64, "PRIVATE_KEY")
    expect(pem).toContain("-----BEGIN RSA PRIVATE KEY-----")
    expect(pem).toContain("-----END RSA PRIVATE KEY-----")
    expect(pem).toContain(base64)
  })

  it("should default to PUBLIC_KEY format", () => {
    const base64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8sC1"
    const pem = convertToPem(base64)
    expect(pem).toContain("-----BEGIN PUBLIC KEY-----")
  })

  it("should wrap base64 at 64 characters", () => {
    const longBase64 = "A".repeat(200)
    const pem = convertToPem(longBase64, "PUBLIC_KEY")
    const lines = pem.split("\n")
    // Check that body lines are at most 64 characters
    const bodyLines = lines.slice(1, -1)
    bodyLines.forEach((line) => {
      expect(line.length).toBeLessThanOrEqual(64)
    })
  })
})
