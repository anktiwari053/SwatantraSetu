import { Router } from 'express';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { store } from '../data/store.js';
import { signToken, authRequired } from '../middleware/auth.js';
import { User } from '../models/index.js';

dotenv.config();

const router = Router();
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;

const mailer = process.env.SMTP_USER && process.env.SMTP_PASS
  ? process.env.SMTP_HOST
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: process.env.SMTP_SECURE === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      })
    : nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      })
  : null;

function publicUser(user) {
  const { password: _, passwordHash: __, otpHash: ___, otpExpiresAt: ____, otpLastSentAt: _____, _id: ______, ...safe } = user.toObject ? user.toObject() : user;
  if (!safe.id && user.id) safe.id = String(user.id);
  return safe;
}

function mongoEnabled() {
  return mongoose.connection.readyState === 1;
}

async function findUserByEmail(email) {
  if (mongoEnabled()) return User.findOne({ email: email.toLowerCase() });
  return store.users.find((candidate) => candidate.email.toLowerCase() === email.toLowerCase());
}

async function findUserById(id) {
  if (mongoEnabled()) return User.findById(id);
  return store.users.find((candidate) => candidate.id === id);
}

async function saveUser(user) {
  if (mongoEnabled() && user.save) await user.save();
}

function issueOtp(user) {
  const otp = String(crypto.randomInt(100000, 1000000));
  user.otpHash = bcrypt.hashSync(otp, 12);
  user.otpExpiresAt = Date.now() + OTP_EXPIRY_MS;
  user.otpLastSentAt = Date.now();
  return otp;
}

async function sendOtpEmail(user, otp) {
  if (!mailer) {
    throw new Error('Email service is not configured');
  }
  await mailer.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: user.email,
    subject: 'Verify your Co-opConnect email',
    text: `Your Co-opConnect verification code is ${otp}. It expires in 5 minutes.`,
    html: `<p>Your Co-opConnect verification code is:</p><p style="font-size:24px;font-weight:bold;letter-spacing:6px">${otp}</p><p>This code expires in 5 minutes.</p>`,
  });
}

async function createAndSendOtp(user) {
  const otp = issueOtp(user);
  try {
    await sendOtpEmail(user, otp);
  } catch (error) {
    user.otpHash = undefined;
    user.otpExpiresAt = undefined;
    user.otpLastSentAt = undefined;
    throw error;
  }
}

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await findUserByEmail(String(email || ''));
  const passwordMatches = user && (user.passwordHash
    ? await bcrypt.compare(String(password || ''), user.passwordHash)
    : user.password === password);
  if (!passwordMatches) return res.status(401).json({ message: 'Invalid email or password' });
  if (user.isEmailVerified === false || (user.isEmailVerified === undefined && user.verified === false)) {
    return res.status(403).json({ message: 'Please verify your email first.' });
  }
  const safe = publicUser(user);
  const token = signToken(safe);
  res.json({ token, user: safe });
});

router.post('/register', async (req, res) => {
  const { name, email, password, role = 'customer', phone, city } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email and password are required' });
  }
  if (await findUserByEmail(email)) {
    return res.status(409).json({ message: 'Account already exists' });
  }
  const user = mongoEnabled()
    ? new User({ name, email: email.toLowerCase(), passwordHash: await bcrypt.hash(password, 12), role, phone: phone || '', city: city || '', verified: false, isEmailVerified: false })
    : {
        id: `u-${Date.now()}`,
        name,
        email,
        password,
        role,
        phone: phone || '',
        city: city || '',
        verified: false,
        isEmailVerified: false,
        languages: ['English', 'Hindi'],
      };
  if (!mongoEnabled()) store.users.push(user);
  try {
    await createAndSendOtp(user);
    await saveUser(user);
  } catch (error) {
    if (!mongoEnabled()) store.users.splice(store.users.indexOf(user), 1);
    console.error('Unable to send verification email:', error.message);
    return res.status(503).json({ message: 'Unable to send verification email. Please try again later.' });
  }
  res.status(201).json({ message: 'Verification code sent.', email: user.email });
});

router.post('/verify-email', async (req, res) => {
  const { email, otp } = req.body || {};
  const user = await findUserByEmail(String(email || ''));
  if (!user) return res.status(404).json({ message: 'Account not found' });
  if (!/^\d{6}$/.test(String(otp || '')) || !user.otpHash || !user.otpExpiresAt) {
    return res.status(400).json({ message: 'Invalid or expired verification code.' });
  }
  if (Date.now() > user.otpExpiresAt || !bcrypt.compareSync(String(otp), user.otpHash)) {
    return res.status(400).json({ message: 'Invalid or expired verification code.' });
  }
  user.isEmailVerified = true;
  user.verified = true;
  user.otpHash = undefined;
  user.otpExpiresAt = undefined;
  user.otpLastSentAt = undefined;
  await saveUser(user);
  const safe = publicUser(user);
  res.json({ message: 'Email verified successfully.', token: signToken(safe), user: safe });
});

router.post('/resend-otp', async (req, res) => {
  const { email } = req.body || {};
  const user = await findUserByEmail(String(email || ''));
  if (!user) return res.status(404).json({ message: 'Account not found' });
  if (user.isEmailVerified || user.verified) {
    return res.status(400).json({ message: 'Email is already verified.' });
  }
  const remaining = user.otpLastSentAt ? RESEND_COOLDOWN_MS - (Date.now() - user.otpLastSentAt) : 0;
  if (remaining > 0) {
    return res.status(429).json({ message: `Please wait ${Math.ceil(remaining / 1000)} seconds before requesting another code.` });
  }
  try {
    await createAndSendOtp(user);
    await saveUser(user);
    res.json({ message: 'A new verification code was sent.' });
  } catch (error) {
    console.error('Unable to resend verification email:', error.message);
    res.status(503).json({ message: 'Unable to send verification email. Please try again later.' });
  }
});

router.get('/me', authRequired, async (req, res) => {
  const user = await findUserById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json(publicUser(user));
});

export default router;
