# Tutorial av gpt.ri.se med korrigeringar och tillägg av Henrik Bygren
I denna tutorial kommer vi att gå igenom en Node.js-applikation som använder `bcrypt` för lösenordshantering, `jsonwebtoken` för autentisering och `cookie` för att hantera användarsessioner. Vi kommer att förklara varje del av koden och hur dessa bibliotek bidrar till säkerheten i applikationen.

Endast filen router.mjs gås igenom. 

För att följa denna tutorial behöver du clona från

   https://github.com/ByHe/docker-nodejs-auth-egytalk


### Konfiguration

Gå till katalogen **server** 

Skapa en `.env`-fil i din projektmapp, om den inte redan finns, och lägg till följande miljövariabler:

```plaintext
HOST="mariadb"
DB="egytalk"
USER="egytalk"
PASSWORD="12345"
JWT_SECRET='dd92080dcabb323966040285d2a903b5f1bff87107b947454106f92692f431a87787070c376e69b163e9fbd5787282358135bc80b7018a46b0d76d109dfcbd0d'
```

### Förutsättningar


I katalogen **server** kör i terminalen 

```bash
npm install 
```

Gå till root-katalogen och kör

```bash
docker compose up -d
```

Öppna phpmyadmin (http://localhost:8080) och importer databasen egytalk. Skapa även användare enligt **.env** filen.

Kör följade sql om du har användare i tabellen user som är skapade med PHP.

```sql
UPDATE user SET password = REPLACE(password, '$2y$', '$2b$') WHERE password LIKE '$2y$%';
```

### Test
För att testa

   http://localhost

De filer som är tillgängliga för att testa ligger i katalogen **html**

### Koden

Här är koden i **router.mjs** med förklaringar:

```javascript
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
 * Endpoint: /api/users
 * Method: POST
 */
router.post('/users', async function (req, res) {
   const result = { success: false }
   const cost = 10

   const { firstName, surName, userName, password } = req.body;

   try {
      const passwordHash = await bcrypt.hash(password, cost);
      const connection = await connectToDB();
      const sql = "INSERT INTO user(uid, firstname, surname, username, password) VALUES(UUID(),?,?,?,?)";
      await connection.execute(sql, [firstName, surName, userName, passwordHash]);
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
 * Endpoint: /api/auth
 * Method: POST
 */
router.post('/auth', async function (req, res) {
   const { userName, password } = req.body;

   const response = await authenticateUser(userName, password);

   if (!response.success) {
      res.json(response)
      return;
   }

   const uid = response.userInfo.uid
   const JWTToken = jwt.sign({ uid }, process.env.JWT_SECRET, { expiresIn: '4h' });

   const cookie = serialize('jwt', JWTToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 14400,
      path: '/'
   });

   res.setHeader('Set-Cookie', cookie)

   res.json(response)
})

/**
 * Middleware för att logga ut användare.
 * Endpoint: /api/logout
 * Method: POST
 */
router.post('/logout', function (req, res) {
   const cookie = serialize('jwt', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      expires: new Date(0),
      path: '/'
   });

   res.setHeader('Set-Cookie', cookie);
   res.json({ success: true });
});

/**
 * Middleware för att autentisera mot en JWT-cookie.
 * Om autentisering lyckas returneras {success: true}.
 * Endpoint: /api/auth
 * Method: GET
 */
router.get('/auth', async function (req, res) {
   const result = await getUserFromCookie(req.headers.cookie)

   res.json(result);
})

/**
 * Middleware för att returnera alla användare om JWT-cookien kan verifieras.
 * Endpoint: /api/users
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
 * Endpoint: /api/*
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

   const token = cookies.jwt;

   if (!token) {
      return response;
   }

   let decodedJWT

   try {
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
```

## Förklaringar

### bcrypt

`bcrypt` används för att hasha lösenord innan de sparas i databasen. Detta gör det svårare för en angripare att få tillgång till användarnas lösenord om databasen skulle bli komprometterad.


```javascript
const passwordHash = await bcrypt.hash(password, cost);
```

**Hur fungerar bcrypt?**
   - **Saltgenerering:** Bcrypt genererar en unik salt för varje lösenord.
   - **Hashing:** Lösenordet kombineras med saltet och genomgår flera rundor (==cost==) av hashing.
   - **Resultat:** Den slutliga hashade strängen lagras i databasen tillsammans med saltet.

**Verifiera lösenord**

När en användare loggar in, hashar du det inskrivna lösenordet och jämför det med den lagrade hashade versionen.

Här är **password** det lösenord som skall testas och **result.userInfo.password** det hashade lösenordet från databasen.

```javascript
if (await bcrypt.compare(password, result.userInfo.password)) 
```

### jsonwebtoken

`jsonwebtoken` används för att skapa och verifiera JSON Web Tokens (JWT). JWT används för att autentisera användare utan att behöva lagra sessionsdata på servern.

```javascript
const JWTToken = jwt.sign({ uid }, process.env.JWT_SECRET, { expiresIn: '4h' });
```

### cookie

`cookie`-biblioteket används för att hantera cookies i HTTP-svar. Cookies används för att lagra JWT på klienten.

```javascript
const cookie = serialize('jwt', JWTToken, {
   httpOnly: true,
   secure: process.env.NODE_ENV === 'production',
   sameSite: 'Strict',
   maxAge: 14400,
   path: '/'
});
```

## Sammanfattning

I denna tutorial har vi gått igenom hur man använder `bcrypt` för lösenordshantering, `jsonwebtoken` för autentisering och `cookie` för att hantera användarsessioner i en Node.js-applikation. Dessa tekniker bidrar till att göra applikationen säkrare genom att skydda användarnas data och autentisera användare på ett säkert sätt.
