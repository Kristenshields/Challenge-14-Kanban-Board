import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  // TODO: verify the token exists and add the user data to the request object
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
     res.status(401).json({ message: 'Access token is missing or invalid' });
     return;
  }
  
  try {
  const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY!) as JwtPayload;
  req.user = decoded;
  next();
  } catch (error) {
     res.status(403).json({ message: 'Token is invalid or expired'});
  }
};
  

