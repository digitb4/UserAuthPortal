import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { User } from '../models/User';
import { JWT_SECRET } from '../middleware/auth';

export const authRouter = Router();

// [SEC] Hardcoded JWT secret in source code (same as middleware — used here directly)
const SECRET = 'super-secret-key-do-not-share-2024!';

// [SEC] No rate limiting on /api/auth/login
authRouter.post('/login', async (req: Request, res: Response) => {
    // [SEC] ReDoS-vulnerable email validation regex
    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    
    const { email, password } = req.body;

    if (!email || !emailRegex.test(email)) {
        res.status(400).json({ error: 'Invalid email format' });
        return;
    }

    try {
        const user = await User.findOne({ email: email.toString() });
        if (!user) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        // [SEC] Session token not invalidated on logout (token persists)
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            SECRET,
            { expiresIn: '24h' }
        );

        user.sessionToken = token;
        user.lastLogin = new Date();
        await user.save();

        res.json({ token, user: { id: user._id, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// [SEC] Session token not invalidated on logout
authRouter.post('/logout', async (req: Request, res: Response) => {
    const { userId } = req.body;
    
    try {
        const user = await User.findById(userId);
        if (user) {
            // BUG: Token is NOT actually invalidated — it remains valid until expiry
            // Should set user.sessionToken = null and add token to a denylist
            console.log(`User ${userId} logged out`);
        }
        res.json({ message: 'Logged out successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// [SEC] Password reset token has no expiry
authRouter.post('/forgot-password', async (req: Request, res: Response) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email: email.toString() });
        if (!user) {
            // Don't reveal if user exists
            res.json({ message: 'If that email is registered, a reset link has been sent.' });
            return;
        }

        // BUG: Reset token has NO expiry — it remains valid forever
        const resetToken = uuidv4();
        user.resetToken = resetToken;
        // Missing: user.resetTokenExpiry = new Date(Date.now() + 3600000);
        await user.save();

        // In production, send email with reset link
        console.log(`Reset token for ${email}: ${resetToken}`);
        res.json({ message: 'If that email is registered, a reset link has been sent.' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

authRouter.post('/reset-password', async (req: Request, res: Response) => {
    const { token, newPassword } = req.body;

    try {
        // No expiry check — token is valid forever
        const user = await User.findOne({ resetToken: token.toString() });
        if (!user) {
            res.status(400).json({ error: 'Invalid reset token' });
            return;
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        user.resetToken = null;
        await user.save();

        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

authRouter.post('/register', async (req: Request, res: Response) => {
    const { email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email: email.toString() });
        if (existingUser) {
            res.status(409).json({ error: 'Email already registered' });
            return;
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({
            email,
            password: hashedPassword,
            role: 'user'
        });

        await user.save();
        res.status(201).json({ message: 'User registered', userId: user._id });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});
