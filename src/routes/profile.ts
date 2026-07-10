import { Router, Request, Response } from 'express';
import { User } from '../models/User';
import { authenticateToken } from '../middleware/auth';

export const profileRouter = Router();

profileRouter.use(authenticateToken);

// [SEC] IDOR — userId taken from req.body instead of JWT claim (read)
profileRouter.get('/', async (req: Request, res: Response) => {
    try {
        // BUG: Takes userId from query params instead of JWT token claim
        // An attacker can read any user's profile by supplying another user's ID
        const userId = req.query.userId || (req as any).user.userId;
        
        const user = await User.findById(userId).select('-password -resetToken');
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        res.json({ profile: user });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// [SEC] IDOR — no ownership check on profile update
profileRouter.put('/', async (req: Request, res: Response) => {
    try {
        // BUG: userId from request body — attacker can update any user's profile
        const { userId, email, role } = req.body;
        
        // No check that req.user.userId === userId
        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }

        if (email) user.email = email;
        if (role) user.role = role; // Also allows role escalation!
        await user.save();

        res.json({ message: 'Profile updated', profile: user });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

profileRouter.get('/me', async (req: Request, res: Response) => {
    try {
        const userId = (req as any).user.userId;
        const user = await User.findById(userId).select('-password -resetToken');
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        res.json({ profile: user });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});
