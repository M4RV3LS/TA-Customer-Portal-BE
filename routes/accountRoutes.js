const express = require("express");
const router = express.Router();
const connection = require("../dbConnection");
const fetch = require("node-fetch");
const crypto = require("crypto");
const { getBankApiBaseUrl } = require("../utils/bankHelper");
const util = require("util");
const QRCode = require("qrcode");
const {
  getPinRecord,
  upsertPin,
  verifyPin,
} = require("../services/pinService");
const { issueOTP } = require("../services/otpService"); // We can reuse the email service

const queryAsync = util.promisify(connection.query).bind(connection);
const AES_ALGORITHM = "aes-256-cbc";

// ✅ ADDED: Complete aesDecrypt function
function aesDecrypt(encryptedTextWithIv, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) throw new Error("Invalid key length for AES-256.");
  const textParts = encryptedTextWithIv.split(":");
  if (textParts.length !== 2) throw new Error("Invalid encrypted text format.");
  const iv = Buffer.from(textParts.shift(), "hex");
  const encryptedText = textParts.join(":");
  if (iv.length !== 16) throw new Error("Invalid IV length.");
  const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// --- MIDDLEWARE FOR SESSION-BASED PIN AUTHORIZATION ---
function isPinVerified(req, res, next) {
  if (
    req.session.isPinVerified &&
    Date.now() - req.session.pinVerifiedAt < 300000
  ) {
    return next();
  }
  delete req.session.isPinVerified;
  delete req.session.pinVerifiedAt;
  return res.status(403).json({
    error:
      "PIN verification required or has expired. Please verify your PIN again.",
  });
}

// POST /account/profile/view (Securely returns decrypted data after PIN auth)
router.post("/profile/view", isPinVerified, async (req, res) => {
  const uid = req.session.userId;
  delete req.session.isPinVerified; // Invalidate PIN after use
  delete req.session.pinVerifiedAt;
  try {
    const [userProfile] = await queryAsync(
      `SELECT encrypted_bundle, decrypt_key FROM user_profiles WHERE user_id = ?`,
      [uid]
    );
    if (
      !userProfile ||
      !userProfile.encrypted_bundle ||
      !userProfile.decrypt_key
    ) {
      return res
        .status(404)
        .json({ error: "No decryptable documents found for this user." });
    }

    // ✅ FIX: The incorrect local function declaration has been removed.
    // This now calls the correct aesDecrypt function from the top of the file.
    const decryptedBundleJsonString = aesDecrypt(
      userProfile.encrypted_bundle,
      userProfile.decrypt_key
    );

    const bundleContent = JSON.parse(decryptedBundleJsonString);

    res.json({
      ktpData: bundleContent.ktpData,
      kycData: bundleContent.kycData,
    });
  } catch (err) {
    console.error(`[POST /account/profile/view] Error for user ${uid}:`, err);
    res.status(500).json({ error: "Failed to decrypt documents." });
  }
});
// ✅ UPDATED: Endpoint to request a PIN reset email with robust URL building.
router.post("/pin/request-reset", async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });

  try {
    const [user] = await queryAsync(
      `SELECT email FROM users_credential WHERE id = ?`,
      [uid]
    );
    if (!user) return res.status(404).json({ error: "User not found." });

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 3600000); // Token expires in 1 hour

    const updateResult = await queryAsync(
      "UPDATE users_credential SET pin_reset_token = ?, pin_reset_expires_at = ? WHERE id = ?",
      [token, expiresAt, uid]
    );

    console.log(
      `[request-reset] DB update result for user ${uid}:`,
      updateResult.message
    );

    // --- Robust URL Generation ---
    const resetUrl = new URL("http://localhost:3000/reset-pin");
    resetUrl.searchParams.set("token", token);
    const finalUrl = resetUrl.toString(); // Produces a correctly encoded URL
    // -----------------------------

    // Send the custom reset email with the securely built URL
    await issueOTP(uid, user.email, {
      subject: "Your PIN Reset Request",
      html: `
        <p>You requested to reset your PIN. Please click the link below to proceed:</p>
        <a href="${finalUrl}" style="display:inline-block;padding:10px 20px;font-size:16px;color:white;background-color:#0d9488;text-decoration:none;border-radius:5px;">Reset Your PIN</a>
        <p>This link is valid for one hour. If you did not request this, please ignore this email.</p>
      `,
    });

    res.json({ message: "PIN reset email sent. Please check your inbox." });
  } catch (e) {
    console.error("[POST /pin/request-reset] Error:", e);
    res.status(500).json({ error: "Failed to send reset email." });
  }
});

// ✅ UPDATED: Endpoint to set a new PIN using a token with better logging
router.post("/pin/reset-with-token", express.json(), async (req, res) => {
  const { token, pin } = req.body;
  if (!token || !pin || !/^\d{6}$/.test(pin)) {
    return res.status(400).json({ error: "Invalid token or PIN format." });
  }

  try {
    // Add this log to see what the backend is looking for
    console.log(
      `[reset-with-token] Attempting to find user with token prefix: ${token.substring(
        0,
        10
      )}...`
    );

    const [user] = await queryAsync(
      "SELECT id FROM users_credential WHERE pin_reset_token = ? AND pin_reset_expires_at > NOW()",
      [token]
    );

    if (!user) {
      console.error(`[reset-with-token] Token not found or expired.`);
      return res.status(400).json({
        message:
          "This reset link is invalid or has expired. Please request a new one.",
      });
    }

    console.log(
      `[reset-with-token] Found user ID: ${user.id}. Proceeding to update PIN.`
    );
    await upsertPin(user.id, pin);
    await queryAsync(
      "UPDATE users_credential SET pin_reset_token = NULL, pin_reset_expires_at = NULL WHERE id = ?",
      [user.id]
    );

    res.json({ message: "Your PIN has been successfully reset." });
  } catch (e) {
    console.error("[POST /pin/reset-with-token] Error:", e);
    res.status(500).json({ error: "Failed to reset PIN." });
  }
});

// --- CORE ACCOUNT ROUTES ---
router.get("/", async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });
  try {
    const [user] = await queryAsync(
      `SELECT id, name, email, phone FROM users_credential WHERE id = ?`,
      [uid]
    );
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (err) {
    console.error("[GET /account] MySQL error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

router.put("/", express.json(), async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });
  const { name, email, phone } = req.body;
  if (!name || !email || !phone) {
    return res.status(400).json({ error: "Missing name, email, or phone" });
  }
  try {
    await queryAsync(
      `UPDATE users_credential SET name = ?, email = ?, phone = ? WHERE id = ?`,
      [name, email, phone, uid]
    );
    res.json({ message: "Account updated successfully" });
  } catch (err) {
    console.error("[PUT /account] MySQL error:", err);
    return res.status(500).json({ error: "Update failed" });
  }
});

// --- PROFILE & DOCUMENT ROUTES (REFACTORED FOR PIN SECURITY) ---

// ✅ REVISED: GET /account/profile with self-healing key regeneration
router.get("/profile", async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });

  try {
    const [userProfile] = await queryAsync(
      `SELECT user_id, first_bank_code, encrypted_bundle, decrypt_key FROM user_profiles WHERE user_id = ?`,
      [uid]
    );

    if (!userProfile) {
      return res.status(404).json({ error: "User profile not found." });
    }

    // --- Self-Healing Logic ---
    if (userProfile.encrypted_bundle && !userProfile.decrypt_key) {
      console.log(
        `[GET /profile] Key is NULL for user ${uid} but bundle exists. Attempting regeneration from Home Bank: ${userProfile.first_bank_code}`
      );
      const homeBankApiUrl = getBankApiBaseUrl(userProfile.first_bank_code);
      if (!homeBankApiUrl) {
        return res.status(500).json({ error: "HOMEBANK_URL_NOT_CONFIGURED" });
      }

      // Fetch the original raw data from the Home Bank's main backend
      const bankRes = await fetch(
        `${homeBankApiUrl}/kyc-requests?client_id=${uid}`
      );
      if (!bankRes.ok) {
        return res.status(502).json({ error: "HOMEBANK_FETCH_ERROR" });
      }

      const kycRequests = await bankRes.json();
      const latestRequest = kycRequests[0]; // Assuming the first one is the latest/relevant one

      if (
        latestRequest &&
        latestRequest.customer_ktp &&
        latestRequest.customer_kyc
      ) {
        // Regenerate key and bundle
        const newKeyHex = crypto.randomBytes(32).toString("hex");
        const bundleString = JSON.stringify({
          ktpData: latestRequest.customer_ktp,
          kycData: latestRequest.customer_kyc,
        });
        const newEncryptedBundle = aesEncrypt(bundleString, newKeyHex);

        // Update the user's profile with the new key and bundle
        await queryAsync(
          `UPDATE user_profiles SET encrypted_bundle = ?, decrypt_key = ?, is_copied = 0, updated_at = NOW() WHERE user_id = ?`,
          [newEncryptedBundle, newKeyHex, uid]
        );
        console.log(
          `[GET /profile] Successfully regenerated key for user ${uid}.`
        );
        // Update userProfile object for the final response
        userProfile.decrypt_key = newKeyHex;
        userProfile.encrypted_bundle = newEncryptedBundle;
      }
    }
    // --- End Self-Healing Logic ---

    const pinRecord = await getPinRecord(uid);
    res.json({
      profileId: userProfile.user_id,
      firstBankCode: userProfile.first_bank_code,
      hasEncryptedBundle: !!userProfile.encrypted_bundle,
      hasPin: !!(pinRecord && pinRecord.pin_code),
    });
  } catch (err) {
    console.error("[GET /account/profile] Error:", err);
    res.status(500).json({ error: "Server error fetching profile" });
  }
});
// POST /account/profile/view (NEW - Securely returns decrypted data after PIN auth)
router.post("/profile/view", isPinVerified, async (req, res) => {
  const uid = req.session.userId;
  delete req.session.isPinVerified; // Invalidate PIN after use
  delete req.session.pinVerifiedAt;
  try {
    const [userProfile] = await queryAsync(
      `SELECT encrypted_bundle, decrypt_key FROM user_profiles WHERE user_id = ?`,
      [uid]
    );
    if (
      !userProfile ||
      !userProfile.encrypted_bundle ||
      !userProfile.decrypt_key
    ) {
      return res
        .status(404)
        .json({ error: "No decryptable documents found for this user." });
    }

    // ✅ FIX: The incorrect local function declaration has been removed.
    // This now calls the correct aesDecrypt function from the top of the file.
    const decryptedBundleJsonString = aesDecrypt(
      userProfile.encrypted_bundle,
      userProfile.decrypt_key
    );

    const bundleContent = JSON.parse(decryptedBundleJsonString);

    await queryAsync(
      `UPDATE user_profiles SET decrypt_key = NULL WHERE user_id = ?`,
      [uid]
    );

    res.json({
      ktpData: bundleContent.ktpData,
      kycData: bundleContent.kycData,
    });
  } catch (err) {
    console.error(`[POST /account/profile/view] Error for user ${uid}:`, err);
    res.status(500).json({ error: "Failed to decrypt documents." });
  }
});

// --- PIN MANAGEMENT ROUTES ---

// PATCH /account/pin — Creates or updates the user's PIN.
router.patch("/pin", express.json(), async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });
  const { pin } = req.body;
  if (!pin || !/^\d{6}$/.test(pin)) {
    return res.status(400).json({ error: "PIN must be a 6-digit number." });
  }
  try {
    await upsertPin(uid, pin);
    res.status(200).json({ message: "PIN has been set successfully." });
  } catch (e) {
    console.error("[PATCH /account/pin] Error:", e);
    res.status(500).json({ error: "Failed to set PIN due to a server error." });
  }
});

// POST /account/pin/verify — Verifies PIN and sets session flag.
router.post("/pin/verify", express.json(), async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(401).json({ error: "Not authenticated" });
  const { pin } = req.body;
  if (!pin || !/^\d{6}$/.test(pin)) {
    return res.status(400).json({ error: "Invalid PIN format." });
  }
  try {
    await verifyPin(uid, pin);
    req.session.isPinVerified = true;
    req.session.pinVerifiedAt = Date.now();
    res.status(200).json({ success: true, message: "PIN Verified" });
  } catch (err) {
    res.status(err.status || 500).json({
      error: err.code || "VERIFICATION_FAILED",
      message: err.message,
      ...err,
    });
  }
});

// --- QR CODE ROUTE (PIN PROTECTED) ---

// GET /account/qr
router.get("/qr", isPinVerified, async (req, res) => {
  const uid = req.session.userId;
  delete req.session.isPinVerified; // Invalidate PIN after use
  delete req.session.pinVerifiedAt;
  try {
    const [user] = await queryAsync(
      `SELECT name,email,phone FROM users_credential WHERE id=?`,
      [uid]
    );
    const [profile] = await queryAsync(
      `SELECT first_bank_code AS homeBankCode FROM user_profiles WHERE user_id=?`,
      [uid]
    );
    if (!user || !profile) {
      return res.status(404).json({ error: "Profile not found" });
    }
    const payload = {
      client_id: uid,
      customer_name: user.name,
      customer_email: user.email,
      customer_phone: user.phone,
      status_request: "reuse_kyc",
      home_bank_code: profile.homeBankCode,
    };
    const dataUrl = await QRCode.toDataURL(JSON.stringify(payload), {
      width: 400,
    });
    res.json({ qrDataUrl: dataUrl });
  } catch (e) {
    console.error("[GET /account/qr] QR generation failed:", e);
    res.status(500).json({ error: "QR generation error" });
  }
});

module.exports = router;
