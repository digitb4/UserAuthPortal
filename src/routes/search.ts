import { Router, Request, Response } from 'express';
import { User } from '../models/User';
import jwt from 'jsonwebtoken';

export const searchRouter = Router();

// Duplicated auth check (should use middleware)
searchRouter.use((req: Request, res: Response, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        res.status(401).json({ error: 'Access token required' });
        return;
    }

    try {
        const decoded = jwt.verify(token, 'super-secret-key-do-not-share-2024!') as any;
        (req as any).user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ error: 'Invalid or expired token' });
    }
});

// Search users by role - IDOR: any authenticated user can search all users
searchRouter.get('/by-role', async (req: Request, res: Response) => {
    try {
        const { role } = req.query;
        // No authorization check - any user can list users by role
        const users = await User.find({ role }).select('-password');
        res.json({ users, count: users.length });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Search users by email pattern - potential ReDoS
searchRouter.get('/by-email', async (req: Request, res: Response) => {
    try {
        const { pattern } = req.query;
        // Using user input directly in regex - ReDoS risk
        const regex = new RegExp(pattern as string, 'i');
        const users = await User.find({ email: regex }).select('-password');
        res.json({ users, count: users.length });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});
