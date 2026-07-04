const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');

// Inscription
const register = async (req, res) => {
  const { nom, email, mot_de_passe, role } = req.body;

  if (!nom || !email || !mot_de_passe) {
    return res.status(400).json({ message: 'Nom, email et mot de passe sont requis.' });
  }

  try {
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Un utilisateur avec cet email existe déjà.' });
    }

    const hashedPassword = await bcrypt.hash(mot_de_passe, 10);

    const newUser = await pool.query(
      'INSERT INTO users (nom, email, mot_de_passe, role) VALUES ($1, $2, $3, $4) RETURNING id, nom, email, role, created_at',
      [nom, email, hashedPassword, role || 'personnel']
    );

    res.status(201).json({ message: 'Utilisateur créé avec succès.', user: newUser.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur lors de l\'inscription.' });
  }
};

// Connexion
const login = async (req, res) => {
  const { email, mot_de_passe } = req.body;

  if (!email || !mot_de_passe) {
    return res.status(400).json({ message: 'Email et mot de passe sont requis.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Email ou mot de passe incorrect.' });
    }

    const validPassword = await bcrypt.compare(mot_de_passe, user.mot_de_passe);
    if (!validPassword) {
      return res.status(401).json({ message: 'Email ou mot de passe incorrect.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(200).json({
      message: 'Connexion réussie.',
      token,
      user: { id: user.id, nom: user.nom, email: user.email, role: user.role },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur lors de la connexion.' });
  }
};

// Profil utilisateur connecté (route protégée)
const getProfile = async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nom, email, role, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Utilisateur non trouvé.' });
    }

    res.status(200).json({ user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur.' });
  }
};

module.exports = { register, login, getProfile };
