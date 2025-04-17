import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import { connectDB } from "./config/mongodb.js";
import { authRouter } from "./routes/authRoutes.js";

const app = express();
const port = process.env.PORT || 5000;
connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true }));

// Endpoints
app.get("/", (req, res) => res.send("API is working correctly"));
app.use("/api/auth", authRouter);


app.listen(port, () => console.log(`the server is running on PORT :  ${port}`));
 