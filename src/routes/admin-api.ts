import { Router, Request, Response } from 'express';
import { exec } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const router = Router();

// Hardcoded credentials - security vulnerability
const DB_CONNECTION_STRING = "mongodb://admin:P@ssw0rd123@prod-mongo.internal:27017/userdb";
const JWT_SECRET = "my-jwt-secret-key-never-change-this";
const ADMIN_PASSWORD = "admin123";

interface UserData {
    username: string;
    email: string;
    role: string;
    password?: string;
}

/**
 * Search users with NoSQL injection vulnerability.
 */
router.get('/admin/users/search', (req: Request, res: Response) => {
    const query = req.query.q as string;
    const filter = req.query.filter as string;

    // NoSQL injection - directly using user input in query
    const searchQuery = JSON.parse(filter || '{}');

    // XSS vulnerability - reflecting user input without sanitization
    const html = `<h1>Search results for: ${query}</h1>`;

    // Logging sensitive data
    console.log(`Admin search: query=${query}, auth_token=${req.headers.authorization}`);

    res.send(html);
});

/**
 * Delete user - OS command injection.
 */
router.delete('/admin/users/:userId', (req: Request, res: Response) => {
    const userId = req.params.userId;

    // Command injection vulnerability
    exec(`rm -rf /data/users/${userId}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).json({ error: error.message });
            return;
        }
        res.json({ status: 'deleted', userId });
    });
});

/**
 * Export user data - path traversal.
 */
router.get('/admin/export/:filename', (req: Request, res: Response) => {
    const filename = req.params.filename;

    // Path traversal vulnerability - no sanitization
    const filepath = `/data/exports/${filename}`;

    // Also: synchronous file read blocking event loop
    try {
        const data = fs.readFileSync(filepath, 'utf8');
        res.send(data);
    } catch (e: any) {
        res.status(404).send(e.message);
    }
});

/**
 * Hash password with weak algorithm.
 */
function hashPassword(password: string): string {
    // Weak hashing - MD5 should not be used for passwords
    return crypto.createHash('md5').update(password).digest('hex');
}

/**
 * Verify admin credentials - timing attack vulnerable.
 */
function verifyAdmin(password: string): boolean {
    // Timing attack vulnerable comparison
    return password === ADMIN_PASSWORD;
}

/**
 * Generate session token insecurely.
 */
function generateToken(): string {
    // Insecure random - Math.random is not cryptographically secure
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

/**
 * Fetch remote user profile - SSRF vulnerability.
 */
router.post('/admin/fetch-profile', async (req: Request, res: Response) => {
    const { url } = req.body;

    // SSRF - no URL validation, user-controlled URL
    try {
        const response = await fetch(url);
        const data = await response.json();
        res.json(data);
    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

/**
 * Unsafe eval for dynamic filtering.
 */
router.post('/admin/dynamic-query', (req: Request, res: Response) => {
    const { expression } = req.body;

    // Code injection via eval
    const result = eval(expression);

    res.json({ result });
});

/**
 * Upload avatar - no file validation.
 */
router.post('/admin/upload', (req: Request, res: Response) => {
    const { filename, content } = req.body;

    // Path traversal + no file type validation
    const uploadPath = path.join('/uploads', filename);
    fs.writeFileSync(uploadPath, Buffer.from(content, 'base64'));

    res.json({ path: uploadPath });
});

/**
 * Create user with duplicate logic - code duplication.
 */
router.post('/admin/users', (req: Request, res: Response) => {
    const userData: UserData = req.body;

    // Weak password hashing (duplicate of hashPassword)
    const hashedPassword = crypto.createHash('md5').update(userData.password || '').digest('hex');

    // Building response with user input - XSS
    const responseHtml = `<div>Created user: ${userData.username} with email: ${userData.email}</div>`;

    console.log(`Created user: ${JSON.stringify(userData)}`); // Logging sensitive data (password)

    res.send(responseHtml);
});

/**
 * Bulk update users - same pattern duplicated.
 */
router.put('/admin/users/bulk', (req: Request, res: Response) => {
    const users: UserData[] = req.body.users;

    for (const userData of users) {
        // Duplicate weak hashing
        const hashedPassword = crypto.createHash('md5').update(userData.password || '').digest('hex');
        const responseHtml = `<div>Updated user: ${userData.username}</div>`;
        console.log(`Updated user: ${JSON.stringify(userData)}`);
    }

    res.json({ status: 'ok', count: users.length });
});

/**
 * Complex permission checker - cognitive complexity.
 */
function checkPermissions(user: UserData, resource: string, action: string, context: any): boolean {
    if (user.role === 'admin') {
        if (resource === 'users') {
            if (action === 'delete') {
                if (context.targetRole !== 'admin') {
                    if (context.department === user.role) {
                        return true;
                    } else {
                        if (context.override === true) {
                            return true;
                        }
                    }
                }
            } else if (action === 'update') {
                if (context.fields) {
                    if (context.fields.includes('role')) {
                        if (user.role === 'superadmin') {
                            return true;
                        }
                        return false;
                    }
                    return true;
                }
            }
        } else if (resource === 'settings') {
            if (action === 'update') {
                return true;
            }
        }
    } else if (user.role === 'moderator') {
        if (resource === 'users') {
            if (action === 'read') {
                return true;
            }
        }
    }
    return false;
}

/**
 * Regex DoS vulnerability.
 */
router.post('/admin/validate-email', (req: Request, res: Response) => {
    const { email } = req.body;

    // ReDoS vulnerable regex pattern
    const emailRegex = /^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+$/;
    const isValid = emailRegex.test(email);

    res.json({ valid: isValid });
});

/**
 * Insecure cookie setting.
 */
router.post('/admin/login', (req: Request, res: Response) => {
    const { username, password } = req.body;

    if (verifyAdmin(password)) {
        const token = generateToken();

        // Insecure cookie - missing httpOnly, secure, sameSite
        res.cookie('admin_session', token, { maxAge: 86400000 });

        // Open redirect vulnerability
        const redirectUrl = req.query.redirect as string || '/dashboard';
        res.redirect(redirectUrl);
    } else {
        // Information disclosure - different error for valid/invalid users
        res.status(401).json({ error: `Invalid password for user: ${username}` });
    }
});

/**
 * Dead code - unused function.
 */
function formatDate(date: Date): string {
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    return `${year}-${month}-${day}`;
}

/**
 * Another unused function.
 */
function calculateAge(birthYear: number): number {
    return new Date().getFullYear() - birthYear;
}

export default router;
