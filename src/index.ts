import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import speakeasy, { GeneratedSecret } from 'speakeasy';
import qrcode from 'qrcode';

const app = express();
app.use(express.json());

const SECRET: string = 'your_jwt_secret'; // Güvenli bir şekilde saklanmalı!

interface User {
    secret: string;
    verified: boolean;
}

const users: Record<string, User> = {};

// 2FA Kodu oluşturma
app.get('/2fa/setup', async (req: Request, res: Response): Promise<void> => {
    const { username } = req.query as { username: string };  // query parametrelerinden alıyoruz
    if (!username) {
        res.status(400).json({ error: 'Kullanıcı adı gerekli' });
        return;
    }

    const secret: GeneratedSecret = speakeasy.generateSecret({ length: 20 });
    users[username as string] = { secret: secret.base32, verified: false };
    
    const otpauth_url: string = secret.otpauth_url || '';
    const qrCodeUrl: string = await qrcode.toDataURL(otpauth_url);
    
    res.send(`
        <html>
            <head>
                <title>2FA Kurulumu</title>
            </head>
            <body>
                <h1>QR Kodunu Tara</h1>
                <img src="${qrCodeUrl}" />
                <p>Veya bu kodu manuel olarak gir: <strong>${secret.base32}</strong></p>
            </body>
        </html>
    `);
});

// 2FA Doğrulama
app.get('/2fa/verify', (req: Request, res: Response): void => {
    const { username, token } = req.query as { username: string; token: string };  // query parametrelerinden alıyoruz
    if (!username || !token) {
        res.status(400).json({ error: 'Eksik bilgi' });
        return;
    }
    
    const user: User | undefined = users[username as string];
    if (!user) {
        res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        return;
    }

    const verified: boolean = speakeasy.totp.verify({
        secret: user.secret,
        encoding: 'base32',
        token
    });
    
    if (verified) {
        user.verified = true;
        const authToken: string = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
        res.json({ success: true, token: authToken });
        return;
    }
    
    res.status(400).json({ error: 'Geçersiz kod' });
});

app.get("/", (req: Request, res: Response): void => {
    //send users
    res.json(users);
});

app.listen(3000, (): void => {
    console.log('Server running on http://localhost:3000');
});
