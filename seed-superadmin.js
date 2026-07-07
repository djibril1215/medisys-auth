require('dotenv').config();
const bcrypt = require('bcrypt');
const pool = require('./src/config/db');

async function seed() {
  const nom = 'Super Admin';
  const email = 'superadmin@medisys.com';
  const motDePasse = 'SuperAdmin123!';
  const role = 'super_admin';

  const hashedPassword = await bcrypt.hash(motDePasse, 10);

  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    console.log('Le super_admin existe deja.');
    process.exit(0);
  }

  await pool.query(
    'INSERT INTO users (nom, email, mot_de_passe, role, hopital_id) VALUES ($1, $2, $3, $4, NULL)',
    [nom, email, hashedPassword, role]
  );

  console.log('Super admin cree avec succes :');
  console.log(`  email : ${email}`);
  console.log(`  mot de passe : ${motDePasse}`);
  process.exit(0);
}

seed().catch((err) => {
  console.error(err);
  process.exit(1);
});
