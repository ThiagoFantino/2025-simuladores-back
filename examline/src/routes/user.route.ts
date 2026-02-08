import { type PrismaClient } from "@prisma/client";
import { Router } from "express";
import bcrypt from "bcryptjs";
import { generateToken, refreshToken } from "../utils/jwt.ts";
import { authenticateToken, requireRole } from "../middleware/auth.ts";

const UserRoute = (prisma: PrismaClient) => {
  const router = Router();

  // Obtener todos los usuarios (protected - professors only)
  router.get('/', authenticateToken, requireRole(['professor', 'system']), async (req, res) => {
    try {
      const users = await prisma.user.findMany({
        select: { id: true, nombre: true, email: true, rol: true },
      });
      res.json(users);
    } catch (error) {
      res.status(500).json({ error: 'Error al obtener los usuarios.' });
    }
  });

  // Obtener un usuario por id (protected)
  router.get('/:id', authenticateToken, async (req, res) => {
    try {
      const targetUserId = parseInt(req.params.id);
      const requestingUserId = req.user!.userId;
      const requestingUserRole = req.user!.rol;

      // Validación de permisos: solo el propietario, profesores o system pueden ver detalles
      if (requestingUserRole === 'student' && requestingUserId !== targetUserId) {
        return res.status(403).json({ error: 'No tienes permisos para ver este usuario' });
      }

      const user = await prisma.user.findUnique({
        where: { id: targetUserId },
        select: { id: true, nombre: true, email: true, rol: true },
      });

      if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado.' });
      }

      res.json(user);
    } catch (error) {
      res.status(500).json({ error: 'Error al obtener el usuario.' });
    }
  });

  // Registrar usuario
  router.post("/signup", async (req, res) => {
    const { nombre, email, password, rol } = req.body;

    try {
      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ error: "El email ya está registrado." });
      }

      // Password is already client-side hashed, now hash it again with bcrypt
      const doubleHashedPassword = await bcrypt.hash(password, 10);

      const user = await prisma.user.create({
        data: {
          nombre,
          email,
          password: doubleHashedPassword,
          rol: rol || "student", // 👈 por defecto student
        },
        select: { id: true, nombre: true, email: true, rol: true },
      });

      res.status(201).json(user);
    } catch (error) {
      console.error("Error al crear el usuario:", error);
      res.status(500).json({ error: "Error al crear el usuario." });
    }
  });

  // Login
  router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
      const user = await prisma.user.findUnique({ where: { email } });

      if (!user) {
        return res.status(404).json({ error: 'El email no está registrado.' });
      }

      // Password comes already client-side hashed, compare with stored double-hashed password
      const isPasswordCorrect = await bcrypt.compare(password, user.password);

      if (!isPasswordCorrect) {
        return res.status(401).json({ error: 'Contraseña incorrecta.' });
      }

      // Generate JWT token
      const tokenPayload = {
        userId: user.id,
        email: user.email,
        nombre: user.nombre,
        rol: user.rol,
      };

      const token = generateToken(tokenPayload);

      return res.json({
        message: 'Login exitoso',
        token, // JWT token
        user: {
          userId: user.id,
          nombre: user.nombre,
          email: user.email,
          rol: user.rol,
        },
      });
    } catch (error) {
      console.error('Error al verificar el usuario:', error);
      return res.status(500).json({ error: 'Hubo un problema al verificar las credenciales' });
    }
  });

  // Token refresh endpoint
  router.post('/refresh-token', authenticateToken, async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Usuario no autenticado' });
      }

      // Generate a new token with the same user data
      const newToken = refreshToken(req.user);

      res.json({
        message: 'Token renovado exitosamente',
        token: newToken,
        user: req.user,
      });
    } catch (error) {
      console.error('Error al renovar token:', error);
      res.status(500).json({ error: 'Error al renovar el token' });
    }
  });

  // Get current user info (protected route)
  router.get('/me', authenticateToken, async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Usuario no autenticado' });
      }

      const user = await prisma.user.findUnique({
        where: { id: req.user.userId },
        select: { id: true, nombre: true, email: true, rol: true },
      });

      if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      res.json(user);
    } catch (error) {
      console.error('Error al obtener información del usuario:', error);
      res.status(500).json({ error: 'Error al obtener información del usuario' });
    }
  });

  router.put('/:id', authenticateToken, async (req, res) => {
  const { nombre, password, currentPassword } = req.body;
  const targetUserId = parseInt(req.params.id);

  try {
    // Todos solo pueden actualizar su propio perfil
    if (req.user!.userId !== targetUserId) {
      return res.status(403).json({ error: 'No tienes permisos para actualizar este usuario' });
    }

    const user = await prisma.user.findUnique({ where: { id: targetUserId } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const dataToUpdate: any = {};
    if (nombre) dataToUpdate.nombre = nombre;

    // Cambiar contraseña
    if (password && password.trim() !== "") {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Debe ingresar la contraseña actual para cambiarla' });
      }

      // Both passwords come client-side hashed, compare with stored double-hashed password
      const isCurrentPasswordCorrect = await bcrypt.compare(currentPassword, user.password);
      if (!isCurrentPasswordCorrect) {
        return res.status(400).json({ error: 'Contraseña actual incorrecta' });
      }

      // Password is already client-side hashed, now hash it again with bcrypt
      dataToUpdate.password = await bcrypt.hash(password, 10);
    }

    const updatedUser = await prisma.user.update({
      where: { id: targetUserId },
      data: dataToUpdate,
      select: { id: true, nombre: true, email: true, rol: true },
    });

    res.json(updatedUser);
  } catch (error) {
    console.error('Error al actualizar usuario:', error);
    res.status(500).json({ error: 'Error actualizando usuario' });
  }
});



  // Eliminar usuario
  /*router.delete('/:id', async (req, res) => {
    try {
      const id = parseInt(req.params.id);

      const user = await prisma.user.findUnique({ where: { id } });
      if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado.' });
      }

      await prisma.user.delete({ where: { id } });

      res.json({ message: 'Usuario eliminado correctamente.' });
    } catch (error) {
      console.error('Error al eliminar usuario:', error);
      res.status(500).json({ error: 'Error al eliminar el usuario.' });
    }
  });*/
// Eliminar usuario y todos sus datos relacionados (cada uno puede borrarse a sí mismo)
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // Solo el propietario puede eliminar su propia cuenta
    if (req.user!.userId !== userId) {
      return res.status(403).json({ error: 'Solo puedes eliminar tu propia cuenta' });
    }

    // Verificar si el usuario existe
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { exams: true }, // Incluye los exámenes que el usuario creó como profesor
    });

    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado." });
    }

    // Obtener todos los IDs de exámenes que el usuario creó
    const examIds = user.exams.map(exam => exam.id);

    // Eliminar en cascada todos los datos relacionados con sus exámenes
    if (examIds.length > 0) {
      // 1. Eliminar archivos de examen de TODOS los usuarios relacionados con estos exámenes
      await prisma.examFile.deleteMany({
        where: { examId: { in: examIds } }
      });

      // 2. Eliminar intentos de examen de TODOS los usuarios
      await prisma.examAttempt.deleteMany({
        where: { examId: { in: examIds } }
      });

      // 3. Eliminar historial de exámenes
      await prisma.examHistory.deleteMany({
        where: { examId: { in: examIds } }
      });

      // 4. Obtener IDs de ventanas de estos exámenes
      const examWindows = await prisma.examWindow.findMany({
        where: { examId: { in: examIds } },
        select: { id: true }
      });
      const windowIds = examWindows.map(w => w.id);

      if (windowIds.length > 0) {
        // 5. Eliminar inscripciones a estas ventanas
        await prisma.inscription.deleteMany({
          where: { examWindowId: { in: windowIds } }
        });

        // 6. Eliminar las ventanas
        await prisma.examWindow.deleteMany({
          where: { id: { in: windowIds } }
        });
      }

      // 7. Eliminar preguntas de los exámenes
      await prisma.pregunta.deleteMany({
        where: { examId: { in: examIds } }
      });

      // 8. Eliminar los exámenes
      await prisma.exam.deleteMany({
        where: { id: { in: examIds } }
      });
    }

    // Eliminar datos del usuario como estudiante
    // 9. Eliminar archivos del usuario en otros exámenes
    await prisma.examFile.deleteMany({
      where: { userId: userId }
    });

    // 10. Eliminar intentos del usuario en otros exámenes
    await prisma.examAttempt.deleteMany({
      where: { userId: userId }
    });

    // 11. Eliminar historial del usuario
    await prisma.examHistory.deleteMany({
      where: { userId: userId }
    });

    // 12. Eliminar inscripciones del usuario
    await prisma.inscription.deleteMany({
      where: { userId: userId }
    });

    // 13. Finalmente, eliminar al usuario
    await prisma.user.delete({ where: { id: userId } });

    res.json({
      message: `Usuario ${user.nombre} y todos sus datos relacionados han sido eliminados completamente.`,
    });
  } catch (error) {
    console.error("Error en el proceso de eliminación:", error);
    res.status(500).json({ error: "Error en el proceso de eliminación del usuario." });
  }
});


  return router;
};



export default UserRoute;
