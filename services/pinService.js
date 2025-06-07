// customer-portal/backend/services/pinService.js
const bcrypt = require("bcrypt");
const util = require("util");
const connection = require("../dbConnection");
const queryAsync = util.promisify(connection.query).bind(connection);

const MAX_ATTEMPTS = 3;
const LOCKOUT_MINUTES = 5;

async function getPinRecord(userId) {
  const [record] = await queryAsync(
    "SELECT pin_code, pin_failed_attempts, pin_locked_until FROM users_credential WHERE id = ?",
    [userId]
  );
  return record || null;
}

async function upsertPin(userId, rawPin) {
  const hash = await bcrypt.hash(rawPin, 10);
  await queryAsync(
    "UPDATE users_credential SET pin_code = ?, pin_failed_attempts = 0, pin_locked_until = NULL WHERE id = ?",
    [hash, userId]
  );
}

async function verifyPin(userId, rawPin) {
  const record = await getPinRecord(userId);
  if (!record || !record.pin_code) {
    throw {
      status: 400,
      code: "PIN_NOT_SET",
      message: "A PIN has not been set for this account.",
    };
  }

  if (
    record.pin_locked_until &&
    new Date(record.pin_locked_until) > new Date()
  ) {
    throw {
      status: 429,
      code: "ACCOUNT_LOCKED",
      message: "Account is locked due to too many failed attempts.",
      retryAfter: record.pin_locked_until,
    };
  }

  const isMatch = await bcrypt.compare(rawPin, record.pin_code);

  if (isMatch) {
    if (record.pin_failed_attempts > 0) {
      await queryAsync(
        "UPDATE users_credential SET pin_failed_attempts = 0, pin_locked_until = NULL WHERE id = ?",
        [userId]
      );
    }
    return true;
  }

  // Handle failed attempt
  const newAttempts = record.pin_failed_attempts + 1;
  let lockoutUntil = null;

  if (newAttempts >= MAX_ATTEMPTS) {
    lockoutUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
  }

  await queryAsync(
    "UPDATE users_credential SET pin_failed_attempts = ?, pin_locked_until = ? WHERE id = ?",
    [newAttempts, lockoutUntil, userId]
  );

  if (lockoutUntil) {
    throw {
      status: 429,
      code: "ACCOUNT_LOCKED",
      message: `Account locked. Please try again in ${LOCKOUT_MINUTES} minutes.`,
      retryAfter: lockoutUntil,
    };
  } else {
    throw {
      status: 400,
      code: "INVALID_PIN",
      message: "Invalid PIN.",
      attemptsLeft: MAX_ATTEMPTS - newAttempts,
    };
  }
}

module.exports = { getPinRecord, upsertPin, verifyPin };
