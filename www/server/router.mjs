import connectToDB from './mariadb/connect.mjs'
import bcrypt from 'bcrypt';
import express from "express"
import jwt from 'jsonwebtoken';
import { serialize, parse } from 'cookie';
import dotenv from 'dotenv'

dotenv.config()
const router = express.Router()

/**
 * Middleware för att lägga till en användare i user-tabellen.
 * Endpoint: localhost/api/users
 * Method: POST
 */
router.post('/users', async function (req, res) {
   const result = { success: false }
   const cost = 10

   // Alternativt: const { firstName, surName, userName, password } = req.body;
   const firstName = req.body.firstName
   const surName = req.body.surName
   const userName = req.body.userName
   const password = req.body.password

   try {
      const hashedPassword = await bcrypt.hash(password, cost);
      const connection = await connectToDB();
      const sql = "INSERT INTO user(uid, firstname, surname, username, password) VALUES(UUID(),?,?,?,?)";
      await connection.execute(sql, [firstName, surName, userName, hashedPassword]);
      connection.end();
      result.success = true;
   } catch (err) {
      console.error(err);
   }

   res.json(result);
})

/**
 * Middleware för att autentisera en användare med användarnamn och lösenord.
 * Om autentisering lyckas skapas en cookie med en JWT och returnerar {success: true}.
 * Endpoint: localhost/api/auth
 * Method: POST
 */
router.post('/auth', async function (req, res) {

   // Alternativt: const { userName, password } = req.body;
   const userName = req.body.userName
   const password = req.body.password

   const response = await authenticateUser(userName, password);

   if (!response.success) {
      res.json(response)
      return;
   }

   const uid = response.userInfo.uid
   const JWTToken = jwt.sign({ uid }, process.env.JWT_SECRET, { expiresIn: '4h' });

   const cookie = serialize('jwt', JWTToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Använd secure flaggan endast i produktion
      sameSite: 'Strict',  // 'Lax'
      maxAge: 14400, // 4 timmar
      path: '/'
   });

   res.setHeader('Set-Cookie', cookie)

   res.json(response)
})

/**
 * Middleware för att logga ut användare.
 * Endpoint: localhost/api/logout
 * Method: POST
 */
router.post('/logout', function (req, res) {
   const cookie = serialize('jwt', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      expires: new Date(0), // Sätter ett utgånget datum
      path: '/'
   });

   res.setHeader('Set-Cookie', cookie);
   res.json({ success: true });
});

/**
 * Middleware för att autentisera mot en JWT-cookie.
 * Om autentisering lyckas returneras {success: true}.
 * Endpoint: localhost/api/auth
 * Method: GET
 */
router.get('/auth', async function (req, res) {
   const result = await getUserFromCookie(req.headers.cookie)

   res.json(result);
})

/**
 * Middleware för att returnera alla användare om JWT-cookien kan verifieras.
 * Endpoint: localhost/api/users
 * Method: GET
 */
router.get('/users', async function (req, res) {
   let result = { success: false, userInfo: [] }
   result = await getUserFromCookie(req.headers.cookie)

   if (!result.success) {
      res.json(result)
      return;
   }

   try {
      const connection = await connectToDB()
      const sql = "SELECT uid, firstName, surName, userName FROM user"
      const [rows,] = await connection.execute(sql)
      connection.end()

      result.success = true
      result.userInfo = rows
   } catch (err) {
      console.error(err);
   }

   res.json(result);
})

/**
 * Middleware för att hantera övriga anrop till domän/api.
 * Endpoint: localhost/api/*
 * Method: GET
 */
router.get('/*', function (req, res) {
   res.json({ success: false })
})

/**
 * Funktion för att autentisera en användare med användarnamn och lösenord.
 * Returnerar all användardata (ej lösenord) om autentisering lyckas.
 * 
 * @param {string} userName 
 * @param {string} password 
 * @returns {Object} { success: false/true, userInfo: [] }
 */
async function authenticateUser(userName, password) {
   let result = { success: false, userInfo: [] }
   try {
      const connection = await connectToDB()
      const sql = "SELECT * FROM user WHERE  username = ?"
      const [rows,] = await connection.execute(sql, [userName])

      connection.end()

      if (rows.length == 1) {
         result.userInfo = rows[0]
         if (await bcrypt.compare(password, result.userInfo.password)) {
            result.success = true;
            delete result.userInfo['password'];
         } else {
            result.userInfo = [];
         }
      }
   } catch (err) {
      console.error(err);
   }

   return result
}

/**
 * Funktion för att autentisera mot en cookie.
 * Om autentisering lyckas returneras all användardata förutom lösenord.
 * 
 * @param {string} cookie 
 * @returns {Object} { success: true/false, userInfo: [] }
 */
async function getUserFromCookie(cookie) {
   let response = { success: false, userInfo: [] }

   if (!cookie) {
      return response;
   }

   const cookies = parse(cookie);

   // Hämta JWT från cookies
   const token = cookies.jwt;

   if (!token) {
      return response;
   }

   let decodedJWT

   try {
      // Verifiera JWT
      decodedJWT = jwt.verify(token, process.env.JWT_SECRET);
   } catch (err) {
      console.error(err)
      return response;
   }

   try {
      const connection = await connectToDB()
      const sql = "SELECT * FROM user WHERE  uid = ?"
      const [rows,] = await connection.execute(sql, [decodedJWT.uid])
      connection.end()

      if (rows.length == 1) {
         response.success = true;
         response.userInfo = rows[0]
         delete response.userInfo['password'];
      }
   } catch (err) {
      console.error(err);
   }

   return response;
}

export default router