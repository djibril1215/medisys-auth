// A utiliser APRES verifyToken, qui a deja peuple req.user
function requireRole(rolesAutorises) {
  return (req, res, next) => {
    if (!req.user || !rolesAutorises.includes(req.user.role)) {
      return res.status(403).json({
        message: 'Acces refuse : role insuffisant pour cette action.',
      });
    }
    next();
  };
}

module.exports = requireRole;
