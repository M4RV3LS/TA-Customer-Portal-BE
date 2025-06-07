// backend/services/otpService.js
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const connection = require("../dbConnection");

const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 5;

require("dotenv").config();

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "marvelsubekti@gmail.com",
    pass: "lbsf ruxp rlxc kgue",
  },
});

function generateOTP() {
  // 100000–999999
  return "" + crypto.randomInt(10 ** (OTP_LENGTH - 1), 10 ** OTP_LENGTH);
}

function saveOTP(userId, otp) {
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60000);
  return new Promise((resolve, reject) => {
    const sql = `INSERT INTO otps (user_id, otp, expires_at, used)
                 VALUES (?, ?, ?, FALSE)`;
    connection.query(sql, [userId, otp, expiresAt], (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function sendOTPEmail(email, otp, customContent = null) {
  const mailOptions = {
    from: '"Your App" <your_email@gmail.com>',
    to: email,
    subject: customContent ? customContent.subject : "Your Login OTP",
    text: customContent
      ? undefined
      : `Your One-Time Password is ${otp} (expires in ${OTP_EXPIRY_MINUTES} min)`,
    html: customContent ? customContent.html : undefined,
  };
  return transporter.sendMail(mailOptions);
}

async function issueOTP(userId, email, customContent = null) {
  if (customContent) {
    // If sending a custom email (like a reset link), we don't need to generate/save an OTP
    await sendOTPEmail(email, null, customContent);
  } else {
    // Original OTP flow
    const otp = generateOTP();
    await saveOTP(userId, otp);
    await sendOTPEmail(email, otp);
  }
}

function verifyOTP(userId, otp) {
  return new Promise((resolve, reject) => {
    const sql = `SELECT id FROM otps
                 WHERE user_id=? AND otp=? AND used=FALSE AND expires_at>NOW()`;
    connection.query(sql, [userId, otp], (err, rows) => {
      if (err) return reject(err);
      if (rows.length === 0) return resolve(false);

      const otpId = rows[0].id;
      connection.query(
        `UPDATE otps SET used=TRUE WHERE id=?`,
        [otpId],
        (err2) => (err2 ? reject(err2) : resolve(true))
      );
    });
  });
}

module.exports = { issueOTP, verifyOTP };
