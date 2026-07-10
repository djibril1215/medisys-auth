const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const pool = require('../config/db');

// Inscription (reservee au super_admin via la route protegee)
const register = async (req, res) => {
  const { nom, email, mot_de_passe, role, hopital_id } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  if (!nom || !email || !mot_de_passe || !role) {
    return res.status(400).json({ message: 'Nom, email, mot de passe et role sont requis.' });
  }

  const rolesValides = ['medecin', 'urgentiste', 'infirmier', 'super_admin'];
  if (!rolesValides.includes(role)) {
    return res.status(400).json({ message: 'Role invalide.' });
  }

  if (role !== 'super_admin' && !hopital_id) {
    return res.status(400).json({ message: "hopital_id est requis pour ce role." });
  }

  try {
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Un utilisateur avec cet email existe déjà.' });
    }

    const hashedPassword = await bcrypt.hash(mot_de_passe, 10);

    const newUser = await pool.query(
      'INSERT INTO users (nom, email, mot_de_passe, role, hopital_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, nom, email, role, hopital_id, created_at',
      [nom, email, hashedPassword, role, hopital_id || null]
    );

    const user = newUser.rows[0];

    // Creation automatique de la fiche personnel (sauf pour le super_admin, qui n'appartient a aucun hopital)
    if (role !== 'super_admin') {
      try {
        const [prenom, ...resteNom] = nom.split(' ').reverse();
        await axios.post(
          `${process.env.PERSONNEL_SERVICE_URL}/api/personnel/internal/from-auth`,
          {
            nom: resteNom.reverse().join(' ') || nom,
            prenom: resteNom.length ? prenom : '',
            email,
            role,
            hopital_id,
            user_id: user.id,
          },
          { headers: { Authorization: `Bearer ${token}` } }
        );
      } catch (syncError) {
        // Si la synchronisation echoue, on annule la creation du compte pour eviter un compte orphelin
        await pool.query('DELETE FROM users WHERE id = $1', [user.id]);
        console.error('Erreur de synchronisation avec medisys-personnel :', syncError.message);
        return res.status(500).json({
          message: "Le compte n'a pas pu etre synchronise avec le service Personnel. Aucun compte n'a ete cree.",
        });
      }
    }

    res.status(201).json({ message: 'Utilisateur créé avec succès.', user });
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
      { id: user.id, email: user.email, role: user.role, hopital_id: user.hopital_id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(200).json({
      message: 'Connexion réussie.',
      token,
      user: {
        id: user.id,
        nom: user.nom,
        email: user.email,
        role: user.role,
        hopital_id: user.hopital_id,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur lors de la connexion.' });
  }
};

// Profil utilisateur connecte
const getProfile = async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nom, email, role, hopital_id, created_at FROM users WHERE id = $1',
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

const getAllUsers = async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nom, email, role, hopital_id, created_at FROM users ORDER BY created_at DESC'
    );
    res.status(200).json({ users: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur.' });
  }
};

// Supprimer un utilisateur - reserve au super_admin, supprime aussi la fiche personnel liee
const deleteUser = async (req, res) => {
  const { id } = req.params;
  const token = req.headers['authorization'].split(' ')[1];

  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ message: 'Vous ne pouvez pas supprimer votre propre compte.' });
  }

  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id, nom, email', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Utilisateur non trouvé.' });
    }

    try {
      await axios.delete(
        `${process.env.PERSONNEL_SERVICE_URL}/api/personnel/internal/by-user/${id}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
    } catch (syncError) {
      console.error('Erreur lors de la suppression de la fiche personnel :', syncError.message);
    }

    res.status(200).json({ message: 'Utilisateur supprimé avec succès.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Erreur serveur lors de la suppression.' });
  }
};

module.exports = { register, login, getProfile, getAllUsers, deleteUser };
