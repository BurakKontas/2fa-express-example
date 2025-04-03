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
    otpTokens: string[];
}

const users: Record<string, User> = {};

// 2FA Kodu oluşturma
app.get('/2fa/setup', async (req: Request, res: Response): Promise<void> => {
    const username = req.query.username as string;  // query parametrelerinden alıyoruz
    if (!username) {
        res.status(400).json({ error: 'Kullanıcı adı gerekli' });
        return;
    }

    const secret: GeneratedSecret = speakeasy.generateSecret({ length: 20 });
    users[username] = { 
        secret: secret.base32, 
        verified: false, 
        otpTokens: [] 
    };
    
    // 8 adet farklı tek seferlik giriş kodu oluşturma
    const otpTokens: string[] = [];
    for (let i = 0; i < 8; i++) {
        const token: string = speakeasy.totp({
            secret: secret.base32,
            encoding: 'base32',
            digits: 8,  // 8 haneli OTP kodları
            time: Math.floor(Date.now() / 1000) + i * 1000  // Her çağrıda farklı zaman kullan
        });
        otpTokens.push(token);
    }
    users[username].otpTokens = otpTokens;

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
                <p>Kullanıcıya 8 adet tek seferlik giriş kodu verilmiştir:</p>
                <ul>
                    ${otpTokens.map((token) => `<li>${token.slice(0, 4) + '-' + token.slice(4, 8)}}</li>`).join('')}
                </ul>
            </body>
        </html>
    `);
});

// 2FA Doğrulama
app.get('/2fa/verify', (req: Request, res: Response): void => {
    const { username, token } = req.query as { username: string; token: string };
    
    if (!username || !token) {
        res.status(400).json({ error: 'Eksik bilgi' });
        return;
    }
    
    const user: User | undefined = users[username];
    if (!user) {
        res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        return;
    }

    // 1. Adım: İlk doğrulama (manuel kod ile kontrol)
    if (token === user.secret) {
        user.verified = true;
        const authToken: string = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
        res.json({ success: true, token: authToken });
        return;
    }

    // 2. Adım: OTP kodu doğrulaması
    if (user.otpTokens.includes(token)) {
        // Geçerli kod ise, bir daha kullanılamaz hale getir
        user.otpTokens = user.otpTokens.filter((t) => t !== token);

        user.verified = true;
        const authToken: string = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
        res.json({ success: true, token: authToken });
        return;
    }
    
    res.status(400).json({ error: 'Geçersiz veya kullanılmış kod' });
});

app.get('/', (req: Request, res: Response): void => {
    res.send(users);
});

app.listen(3000, (): void => {
    console.log('Server running on http://localhost:3000');
});
