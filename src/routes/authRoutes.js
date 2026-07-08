const express = require('express');
const router = express.Router();
const { register, login, getProfile, getAllUsers, deleteUser } = require('../controllers/authController');
const verifyToken = require('../middlewares/authMiddleware');
const requireRole = require('../middlewares/requireRole');

router.post('/login', login);
router.get('/profile', verifyToken, getProfile);

// Reserve au super_admin
router.post('/register', verifyToken, requireRole(['super_admin']), register);
router.get('/users', verifyToken, requireRole(['super_admin']), getAllUsers);
router.delete('/users/:id', verifyToken, requireRole(['super_admin']), deleteUser);

module.exports = router;
