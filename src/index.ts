import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import speakeasy, { GeneratedSecret } from 'speakeasy';
import qrcode from 'qrcode';
import { randomUUID } from 'crypto';

const app = express();
app.use(express.json());

const SECRET: string = randomUUID();

interface User {
    secret: string;
    verified: boolean;
    otpTokens: string[];
}

const users: Record<string, User> = {};

app.get('/2fa/setup', async (req: Request, res: Response): Promise<void> => {
    const username = req.query.username as string;
    if (!username) {
        res.status(400).json({ error: 'Username required' });
        return;
    }

    const secret: GeneratedSecret = speakeasy.generateSecret({ length: 20 });
    users[username] = { 
        secret: secret.base32, 
        verified: false, 
        otpTokens: [] 
    };

    const otpauth_url: string = secret.otpauth_url || '';
    const qrCodeUrl: string = await qrcode.toDataURL(otpauth_url);
    
    res.send(`
        <html>
            <head>
                <title>2FA Setup</title>
            </head>
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
    
    const user: User | undefined = users[username];
    if (!user) {
        res.status(404).json({ error: 'Invalid user' });
        return;
    }

    var otpVerified = verifyOtp(username, token);
    if (otpVerified) {
        var response = {};

        if(!user.verified) {
            const otpTokens: string[] = [];
            for (let i = 0; i < 8; i++) {
                const token: string = speakeasy.totp({
                    secret: user.secret,
                    encoding: 'base32',
                    digits: 6,
                    time: Math.floor(Date.now() / 1000) + i * 1000
                });
                otpTokens.push(token);
            }

            user.otpTokens = otpTokens;

            response = {...response, otpTokens};
        }

        user.verified = true;
        const authToken: string = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
        res.json({ success: true, token: authToken, ...response });
        return;
    } else if (user.otpTokens.includes(token)) {
        user.otpTokens = user.otpTokens.filter((t) => t !== token);

        user.verified = true;
        const authToken: string = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
        res.json({ success: true, token: authToken });
        return;
    }
    
    res.status(400).json({ error: 'Invalid or used code.' });
});

app.get('/', (req: Request, res: Response): void => {
    res.send(users);
});

app.listen(3000, (): void => {
    console.log('Server running on http://localhost:3000');
});

function verifyOtp(username: string, code: string): boolean {
    const user = users[username];

    if (!user) {
        console.error('No user');
        return false;
    }

    const isValid = speakeasy.totp.verify({
        secret: user.secret,
        encoding: 'base32',
        token: code,
        window: 1
    });

    return isValid;
}