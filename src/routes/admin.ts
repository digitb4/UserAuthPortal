import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/User';
import { JWT_SECRET } from '../middleware/auth';

export const adminRouter = Router();

// [ARCH] Auth logic duplicated inline instead of shared middleware
// Instead of using the authenticateToken middleware, this duplicates JWT verification inline
adminRouter.use((req: Request, res: Response, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        res.status(401).json({ error: 'Access token required' });
        return;
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as any;

        if (decoded.role !== 'admin') {
            res.status(403).json({ error: 'Admin access required' });
            return;
        }

        (req as any).user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ error: 'Invalid or expired token' });
    }
});

adminRouter.get('/users', async (req: Request, res: Response) => {
    try {
        const users = await User.find().select('-password -resetToken');
        res.json({ users, total: users.length });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

adminRouter.put('/users/:id/role', async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const { role } = req.body;

        if (!['user', 'admin', 'moderator'].includes(role)) {
            res.status(400).json({ error: 'Invalid role' });
            return;
        }

        const user = await User.findByIdAndUpdate(id, { role }, { new: true });
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        res.json({ message: 'Role updated', user });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

adminRouter.delete('/users/:id', async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const user = await User.findByIdAndDelete(id);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        res.json({ message: 'User deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});
