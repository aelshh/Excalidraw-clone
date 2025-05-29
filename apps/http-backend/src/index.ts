import express from "express";
import { z } from "zod";
import prisma from "@repo/db";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import path from "path";
import bcrypt from "bcrypt";
import cors from "cors";
import authMiddleware from "./middlewares/authMiddleware";

dotenv.config();

const app = express();
const port = 3001;

app.use(express.json());
app.use(cors());

const signupSchema = z.object({
  email: z.string().email(),
  password: z
    .string()
    .min(5, "Password must be atleast 5 charecters")
    .max(100, "Password can be atmost 100 charecters")
    .regex(
      /^(?=.*[A-Za-z])(?=.*\d).+$/,
      "Password must contain atlest one number and one letter"
    ),
});
const signinSchema = z.object({
  email: z.string().email(),
  password: z
    .string()
    .min(5, "Password must be atleast 5 charecters")
    .max(100, "Password can be atmost 100 charecters")
    .regex(
      /^(?=.*[A-Za-z])(?=.*\d).+$/,
      "Password must contain atlest one number and one letter"
    ),
});

app.post("/api/v1/signup", async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      message: "Invalid Inputs",
      error: parsed.error.errors,
    });
    return;
  }
  const { email, password } = parsed.data;

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    if (!process.env.JWT_SECRET) {
      throw new Error("Missing JWT_SECRET environment variable");
    }

    const userExist = await prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (userExist) {
      res.status(409).json({
        message: "Email already exits",
      });
      return;
    }
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    if (!user) {
      res.status(500).json({
        message: "Some internal Error",
      });
      return;
    }

    const token = jwt.sign(
      {
        userId: user.id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      message: "You are signed up successfully",
      token,
    });
  } catch (e) {
    res.status(500).json({
      message: "Some unexpected Error",
    });
    console.log(e);
    return;
  }
});

app.post("/api/v1/signin", async (req, res) => {
  const parsed = signinSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      message: "Invalid Inputs",
      error: parsed.error.errors,
    });
    return;
  }
  const { email, password } = parsed.data;

  try {
    const user = await prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (!user) {
      res.status(404).json({
        message: "User does not exist",
      });
      return;
    }

    const verify = await bcrypt.compare(password, user.password);

    if (!verify) {
      res.status(401).json({
        message: "Incorrect Password",
      });
      return;
    }

    if (!process.env.JWT_SECRET) {
      throw new Error("Missing JWT_SECRET environment variable");
    }
    const token = jwt.sign(
      {
        userId: user.id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      message: "You are signed in successfully",
      token,
    });
  } catch (e) {
    res.status(500).json({
      message: "Some unexpected Error",
    });
    console.log(e);
    return;
  }
});

app.get("/api/v1/create-room/:slug", authMiddleware, async (req, res) => {
  const slug = req.params.slug;
  try {
    const room = await prisma.room.create({
      data: {
        slug: slug!,
        adminId: req.userId!,
      },
    });

    res.json({
      message: "Created room",
      roomId: room.id,
    });
  } catch (e) {
    res.status(500).json({
      message: "Some unexpected Error",
    });
    console.log(e);
    return;
  }
});

app.listen(port, () => console.log(`Server is running on port: ${port}`));
