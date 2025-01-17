import mysql from 'mysql2/promise'
import dotenv from 'dotenv'

dotenv.config()

export default async function connectToDB() {
   const connection = await mysql.createConnection({
      host: process.env.HOST,
      user: process.env.USER,
      password: process.env.PASSWORD,
      database: process.env.DB
   });


   return connection
}
