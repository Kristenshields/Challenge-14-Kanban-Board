import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const login = async (req: Request, res: Response) => {
  // TODO: If the user exists and the password is correct, return a JWT token
  const { username, password } = req.body;

  const user = await User.findOne({where: {username}});

  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  const passwordCorrect = await bcrypt.compare(password, user.password);

  if (!passwordCorrect) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  const secretKey = process.env.JWT_SECRET;

  if (!secretKey) {
    return res.status(500).json({ error: 'Internal server error' });
  }

  const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1h' });
  return res.json({ token });
};



const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;