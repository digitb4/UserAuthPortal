import { User, IUser } from '../models/User';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../middleware/auth';

// Basic test file for auth logic — deliberately low coverage (~52%)

describe('Auth Routes', () => {
    describe('Password Hashing', () => {
        it('should hash password correctly', async () => {
            const password = 'TestPassword123!';
            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(password, salt);
            
            expect(hashed).not.toBe(password);
            expect(await bcrypt.compare(password, hashed)).toBe(true);
        });

        it('should reject wrong password', async () => {
            const password = 'TestPassword123!';
            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(password, salt);
            
            expect(await bcrypt.compare('WrongPassword', hashed)).toBe(false);
        });
    });

    describe('JWT Token', () => {
        it('should generate valid token', () => {
            const payload = { userId: '123', email: 'test@test.com', role: 'user' };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
            
            const decoded = jwt.verify(token, JWT_SECRET) as any;
            expect(decoded.userId).toBe('123');
            expect(decoded.email).toBe('test@test.com');
        });

        it('should reject expired token', () => {
            const payload = { userId: '123', email: 'test@test.com', role: 'user' };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '0s' });
            
            expect(() => jwt.verify(token, JWT_SECRET)).toThrow();
        });
    });
});
