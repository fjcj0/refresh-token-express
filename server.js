import cookieParser from 'cookie-parser';
import 'dotenv/config';
import express from 'express';
import { generateAccessToken, generateRefreshToken } from './utils/generateTokens.js';
import jwt from 'jsonwebtoken';
import { verifyUser } from './middleware/verifyUser.js';
import bcrypt from 'bcryptjs';
const app = express();
app.use(express.json());
app.use(cookieParser());
const users = [
    { id: 1, name: 'Ayham', password: bcrypt.hashSync("Ayham", 10) }
];
app.post('/login', (request, response) => {
    const { username, password } = request.body;
    if (!username || !password)
        return response.status(400).json({ success: false, error: "All fields are required" });
    const user = users.find(u => u.name === username);
    if (!user)
        return response.status(400).json({ success: false, error: "Invalid credentials" });
    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch)
        return response.status(400).json({ success: false, error: "Invalid credentials" });
    const payload = { id: user.id, username: user.name };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);
    response.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: "strict",
        path: "/",
    });
    return response.status(200).json({
        success: true,
        accessToken,
        refreshToken
    });
});
app.post('/refresh', (request, response) => {
    const refreshToken = request.cookies.refreshToken;
    if (!refreshToken)
        return response.status(401).json({ success: false, error: "Unauthorized user" });
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (error, user) => {
        if (error)
            return response.status(403).json({ success: false, error: "Invalid token" });
        const payload = { id: user.id, username: user.username };
        const newAccessToken = generateAccessToken(payload);
        return response.status(200).json({ success: true, accessToken: newAccessToken });
    });
});
app.post('/logout', (request, response) => {
    response.clearCookie("refreshToken");
    return response.status(200).json({ success: true, message: "Logged out successfully" });
});
app.get('/user', verifyUser, (request, response) => {
    return response.status(200).json({ user: request.user });
});
app.listen(process.env.PORT, () =>
    console.log(`Server running at http://localhost:${process.env.PORT}`)
);