import { Router } from 'express';
import { refreshToken, logout } from '../middleware/auth';

const router = Router();

// Token refresh endpoint
router.post('/refresh', refreshToken);

// Logout endpoint
router.post('/logout', logout);

export { router as authRoutes };