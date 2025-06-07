//path file: customer-portal/backend/authRoutes.js
const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const connection = require("./dbConnection");
const { issueOTP, verifyOTP } = require("./services/otpService");

// Encryption configuration for AES decryption
const ENCRYPTION_KEY =
  "90e0f911685aa97fdb56af2016e8ff5eb22b1d2c1de67eb508a305a8a840a145"; // 64-character hex string (32 bytes)
const IV_LENGTH = 16;

function decrypt(text) {
  const textParts = text.split(":");
  const iv = Buffer.from(textParts.shift(), "hex");
  const encryptedText = Buffer.from(textParts.join(":"), "hex");
  const key = Buffer.from(ENCRYPTION_KEY, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Configure Nodemailer transporter (update credentials)
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "marvelsubekti@gmail.com",
    pass: "lbsf ruxp rlxc kgue",
  },
});

// --- Revised Registration Endpoint ---
router.post("/register", (req, res) => {
  try {
    const name = decrypt(req.body.name);
    const email = decrypt(req.body.email);
    const phone = decrypt(req.body.phone);
    const password = decrypt(req.body.password);

    bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
      if (hashErr) return res.status(500).json({ error: "Server error" });

      const verificationToken = crypto.randomBytes(32).toString("hex");
      const query = `
        INSERT INTO users_credential_temp
          (name, email, phone, password, verification_token)
        VALUES (?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          name               = VALUES(name),
          email              = VALUES(email),
          phone              = VALUES(phone),
          password           = VALUES(password),
          verification_token = VALUES(verification_token),
          created_at         = CURRENT_TIMESTAMP
      `;

      connection.query(
        query,
        [name, email, phone, hashedPassword, verificationToken],
        (err) => {
          if (err) {
            console.error("MySQL error:", err);
            return res.status(500).json({ error: "Registration failed" });
          }

          // send verification email…
          const verifyUrl = `http://localhost:3002/auth/verify?token=${verificationToken}`;
          transporter.sendMail(
            {
              from: '"Your App" <your_email@gmail.com>',
              to: email,
              subject: "Email Verification",
              html: `<p>Click to verify:</p>
                   <a href="${verifyUrl}">Verify Now</a>`,
            },
            (mailErr) => {
              if (mailErr) {
                console.error("Email error:", mailErr);
                return res
                  .status(500)
                  .json({ error: "Failed to send verification email" });
              }
              res.json({
                message:
                  "Registration successful. Please check your email for the verification link.",
              });
            }
          );
        }
      );
    });
  } catch (e) {
    console.error("Registration exception:", e);
    res.status(500).json({ error: "Registration failed" });
  }
});

// --- Revised Email Verification Endpoint ---
router.get("/verify", (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send("Invalid token.");

  // 1) Fetch from temp
  connection.query(
    "SELECT * FROM users_credential_temp WHERE verification_token = ?",
    [token],
    (err, rows) => {
      if (err) {
        console.error("[CP Verify] MySQL error fetching temp user:", err);
        return res.status(500).send("Server error fetching temp user.");
      }
      if (rows.length === 0) {
        return res.status(400).send("Invalid or expired verification token.");
      }

      const tempUser = rows[0];

      // 2) Insert into permanent users_credential, ignoring duplicates on email
      const insertPermanentUserSql = `
        INSERT INTO users_credential 
          (name, email, phone, password, verified, verified_at)
        VALUES (?, ?, ?, ?, TRUE, CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE verified = TRUE, verified_at = CURRENT_TIMESTAMP, name = VALUES(name), phone = VALUES(phone), password = VALUES(password)
      `; // Using ON DUPLICATE KEY UPDATE to handle re-verification attempts gracefully

      connection.query(
        insertPermanentUserSql,
        [tempUser.name, tempUser.email, tempUser.phone, tempUser.password],
        (err2, insertResult) => {
          if (err2) {
            console.error(
              "[CP Verify] MySQL error inserting into users_credential:",
              err2
            );
            return res.status(500).send("Error finalizing registration.");
          }

          // Get the user_id of the now permanent user
          // If insertResult.insertId is 0, it means ON DUPLICATE KEY UPDATE happened.
          // We need to fetch the ID based on email if it was an update.
          let permanentUserId = insertResult.insertId;

          const fetchUserIdAndInitializeProfile = (userIdToInit) => {
            // 3) Create a basic entry in user_profiles if it doesn't exist
            // This ensures /account/profile doesn't 404 for new users.
            const initUserProfileSql = `
              INSERT IGNORE INTO user_profiles (user_id, first_bank_code, encrypted_bundle, decrypt_key) 
              VALUES (?, NULL, NULL, NULL)
            `;
            connection.query(
              initUserProfileSql,
              [userIdToInit],
              (errInitProfile) => {
                if (errInitProfile) {
                  console.error(
                    `[CP Verify] MySQL error initializing user_profiles for user_id ${userIdToInit}:`,
                    errInitProfile
                  );
                  // Non-fatal for verification flow, but log it. User might have issues with /account/profile later.
                } else {
                  console.log(
                    `[CP Verify] Initialized user_profiles record for user_id ${userIdToInit}.`
                  );
                }

                // 4) Delete temp row (regardless of profile init error)
                connection.query(
                  "DELETE FROM users_credential_temp WHERE verification_token = ?",
                  [token],
                  (err3) => {
                    if (err3)
                      console.error(
                        "[CP Verify] Error deleting temp row:",
                        err3
                      );
                    // 5) Finally, send them to login
                    console.log(
                      `[CP Verify] User ${tempUser.email} (ID: ${userIdToInit}) verified successfully. Redirecting to login.`
                    );
                    return res.redirect("http://localhost:3000/"); // Redirect to frontend login page
                  }
                );
              }
            );
          };

          if (permanentUserId) {
            // New user inserted
            fetchUserIdAndInitializeProfile(permanentUserId);
          } else {
            // User already existed, ON DUPLICATE KEY UPDATE occurred. Fetch their ID.
            connection.query(
              "SELECT id FROM users_credential WHERE email = ?",
              [tempUser.email],
              (errFetchId, idRows) => {
                if (errFetchId || !idRows.length) {
                  console.error(
                    `[CP Verify] Could not retrieve ID for existing user ${tempUser.email}:`,
                    errFetchId
                  );
                  return res
                    .status(500)
                    .send("Error finalizing registration after update.");
                }
                permanentUserId = idRows[0].id;
                fetchUserIdAndInitializeProfile(permanentUserId);
              }
            );
          }
        }
      );
    }
  );
});

// --- Login Endpoint ---
// router.post('/login', (req, res) => {
//   try {
//     const email = decrypt(req.body.email);
//     const password = decrypt(req.body.password);
//     const query = 'SELECT * FROM users_credential WHERE email = ?';
//     connection.query(query, [email], (err, results) => {
//       if (err) {
//         console.error('MySQL error on login:', err);
//         return res.status(500).json({ error: 'Server error' });
//       }
//       if (results.length === 0) {
//         return res.status(400).json({ error: 'Invalid credentials.' });
//       }
//       const user = results[0];
//       if (!user.verified) {
//         return res.status(400).json({ error: 'Please verify your email before logging in.' });
//       }
//       bcrypt.compare(password, user.password, (err, isMatch) => {
//         if (err) {
//           console.error('Bcrypt error:', err);
//           return res.status(500).json({ error: 'Server error' });
//         }
//         if (!isMatch) {
//           return res.status(400).json({ error: 'Invalid credentials.' });
//         }
//         // Store user ID in session
//         req.session.userId = user.id;

//         return res.json({ message: 'Login successful.', user_id: user.id });
//       });
//     });
//   } catch (error) {
//     console.error('Login exception:', error);
//     res.status(500).json({ error: 'Login failed.' });
//   }
// });

// --- LOGIN STEP 1: credentials check + issue OTP ---
router.post("/login", (req, res) => {
  let email, password;
  try {
    if (!req.body.email || !req.body.password) {
      throw new Error("Missing encrypted fields");
    }
    email = decrypt(req.body.email);
    password = decrypt(req.body.password);
  } catch (err) {
    console.error("❌ [LOGIN] decrypt error:", err.message);
    return res.status(400).json({
      error: "Invalid encryption format — please check your encrypt util",
    });
  }

  connection.query(
    `SELECT id, email, password, verified FROM users_credential WHERE email=?`,
    [email],
    async (err, rows) => {
      // ✅ FIX: Only log an error if one actually occurs.
      if (err) {
        console.error("[LOGIN ERROR] Failed to process login:", err);
        return res.status(500).json({ error: "Server error" });
      }

      if (!rows.length) {
        return res.status(400).json({ error: "Invalid credentials" });
      }

      const user = rows[0];
      if (!user.verified) {
        return res.status(400).json({ error: "Email not verified" });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(400).json({ error: "Invalid credentials" });
      }

      // Store temp userId while waiting for OTP
      req.session.tempUserId = user.id;

      // Issue OTP
      try {
        await issueOTP(user.id, user.email);
        return res.json({
          otpRequired: true,
          message: "OTP sent to your email",
        });
      } catch (e) {
        console.error("[LOGIN] Failed to send OTP:", e);
        return res.status(500).json({ error: "Failed to send OTP" });
      }
    }
  );
});

// --- LOGIN STEP 2: OTP verification ---
router.post("/verify-otp", express.json(), async (req, res) => {
  const userId = req.session.tempUserId;
  const { otp } = req.body;
  if (!userId) return res.status(400).json({ error: "No login in progress" });

  try {
    const ok = await verifyOTP(userId, otp);
    if (!ok) return res.status(400).json({ error: "Invalid or expired OTP" });

    req.session.userId = userId;
    delete req.session.tempUserId;
    return res.json({ message: "Login successful" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "OTP verification failed" });
  }
});

// --- Logout Endpoint ---
router.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    res.clearCookie("connect.sid"); // clears the session cookie
    return res.json({ message: "Logout successful" });
  });
});

// Check Authentication Endpoint
router.get("/check", (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ authenticated: true });
  } else {
    return res.status(401).json({ authenticated: false });
  }
});

// right below your existing /verify-otp handler
router.post("/resend-otp", async (req, res) => {
  const userId = req.session.tempUserId;
  if (!userId) {
    return res.status(400).json({ error: "No login in progress" });
  }
});

module.exports = router;
