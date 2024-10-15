import express from "express"
import cors from "cors"

import router from "./router.mjs"

const app = express()

// ---- Middleware ----
app.use(cors()) // Tillåter anrop från annan domän'
app.use(express.urlencoded({extended: true})) // body urlencoded
app.use(express.json()) // body i json-formatet

app.use(async function(req, res, next){
   console.log("Hello Express Server")
   next(); // Går vidare till nästa middleware-funktion
})

app.use(router)

// -- End Middleware --

/** Startar servern och lyssnar på port 3000 */
app.listen(5000) 