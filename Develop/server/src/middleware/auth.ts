import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // TODONE: verify the token exists and add the user data to the request object
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  const secretKey = process.env.JWT_SECRET;

  if (!secretKey) {
    return res.status(500).json({ message: 'Internal Server Error' });
  }

  try {
    const user = jwt.verify(token, secretKey) as JwtPayload;
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Forbidden' });
  }
};
