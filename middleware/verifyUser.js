import jwt from 'jsonwebtoken';
export const verifyUser = (request, response, next) => {
    const authHeader = request.headers.authorization;
    if (!authHeader)
        return response.status(401).json({ success: false, error: "Unauthorized user" });
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.ACCESS_TOKEN, (err, user) => {
        if (err)
            return response.sendStatus(403);
        request.user = user;
        next();
    });
};