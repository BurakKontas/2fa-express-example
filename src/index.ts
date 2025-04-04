import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import speakeasy, { GeneratedSecret } from 'speakeasy';
import qrcode from 'qrcode';
import { randomUUID } from 'crypto';
import Database from 'better-sqlite3';

const app = express();
app.use(express.json());

const SECRET: string = randomUUID();
const db = new Database('2fa.sqlite');

interface DBUser {
    username: string;
    secret: string;
    verified: number;
}


// DB tablo oluşturma
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        secret TEXT,
        verified INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS otp_tokens (
        username TEXT,
        token TEXT,
        FOREIGN KEY(username) REFERENCES users(username)
    );
`);

app.get('/2fa/setup', async (req: Request, res: Response): Promise<void> => {
    const username = req.query.username as string;
    if (!username) {
        res.status(400).json({ error: 'Username required' });
        return;
    }

    const secret: GeneratedSecret = speakeasy.generateSecret({ length: 20 });

    const insert = db.prepare(`INSERT OR REPLACE INTO users (username, secret, verified) VALUES (?, ?, 0)`);
    insert.run(username, secret.base32);

    const otpauth_url: string = secret.otpauth_url || '';
    const qrCodeUrl: string = await qrcode.toDataURL(otpauth_url);

    res.send(`
        <html>
            <head><title>2FA Setup</title></head>
            <body>
                <h1>Scan QR Code</h1>
                <img src="${qrCodeUrl}" />
                <p>Secret: <strong>${secret.base32}</strong></p>
                <form action="/2fa/verify" method="get">
                    <input type="hidden" name="username" value="${username}" />
                    <input type="text" name="token" placeholder="Enter OTP" required />
                    <button type="submit">Verify</button>
                </form>
            </body>
        </html>
    `);
});

app.get('/2fa/verify', (req: Request, res: Response): void => {
    const { username, token } = req.query as { username: string; token: string };

    if (!username || !token) {
        res.status(400).json({ error: 'Missing information' });
        return;
    }

    const user = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username) as DBUser | undefined;
    if (!user) {
        res.status(404).json({ error: 'Invalid user' });
        return;
    }

    const usedToken = db.prepare(`SELECT * FROM otp_tokens WHERE username = ? AND token = ?`).get(username, token);
    if (usedToken) {
        db.prepare(`DELETE FROM otp_tokens WHERE username = ? AND token = ?`).run(username, token);
        db.prepare(`UPDATE users SET verified = 1 WHERE username = ?`).run(username);

        const authToken = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
        res.json({ success: true, token: authToken });
        return;
    }

    const otpVerified = verifyOtp(user.secret, token);
    if (otpVerified) {
        const isFirstTime = !user.verified;
        const response: any = {};

        if (isFirstTime) {
            const otpTokens: string[] = [];
            for (let i = 0; i < 8; i++) {
                const tok = speakeasy.totp({
                    secret: user.secret,
                    encoding: 'base32',
                    digits: 6,
                    time: Math.floor(Date.now() / 1000) + (i + 1) * 1000
                });
                otpTokens.push(tok);
                db.prepare(`INSERT INTO otp_tokens (username, token) VALUES (?, ?)`).run(username, tok);
            }
            response.otpTokens = otpTokens;
        }

        db.prepare(`UPDATE users SET verified = 1 WHERE username = ?`).run(username);

        const authToken = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
        res.json({ success: true, token: authToken, ...response });
        return;
    }

    res.status(400).json({ error: 'Invalid or used code.' });
});

app.get('/', (req: Request, res: Response): void => {
    const allUsers = db.prepare(`SELECT username, secret, verified FROM users`).all();
    res.json(allUsers);
});

app.listen(3000, (): void => {
    console.log('Server running on http://localhost:3000');
});

function verifyOtp(secret: string, code: string): boolean {
    return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token: code,
        window: 1
    });
}
