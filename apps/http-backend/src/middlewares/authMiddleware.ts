import express, { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import path from "path";

dotenv.config({ path: "../../.env" });

export default function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({
      message: "No token provided",
    });
    return;
  }
  const token = authHeader?.split(" ")[1];

  if (!process.env.JWT_SECRET) {
    throw new Error("Missing JWT_SECRET environment variable");
  }

  try {
    const { userId } = jwt.verify(token!, process.env.JWT_SECRET) as {
      userId: string;
    };
    if (!userId) {
      res.status(401).json({
        message: "Invalid token",
      });
      return;
    }

    req.userId = userId;
    next();
  } catch (e) {
    res.status(401).json({
      message: "Some unexpected Error",
    });
    console.log(e);
    return;
  }
}
