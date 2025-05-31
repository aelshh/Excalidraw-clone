import { WebSocketServer, WebSocket } from "ws";
import jwt, { JwtPayload } from "jsonwebtoken";
import dotenv from "dotenv";
import { parse } from "url";

dotenv.config({ path: "../../.env" });

const wss = new WebSocketServer({ port: 8080 });

function auth(token: string) {
  if (!process.env.JWT_SECRET) {
    throw new Error("Missing JWT_SECRET environment variable");
  }
  const { userId } = jwt.verify(token, process.env.JWT_SECRET) as JwtPayload;
  if (!userId) {
    return null;
  }
  return userId;
}

type User = {
  userId: number;
  ws: WebSocket;
  rooms?: string[];
};

const users: User[] = [];

wss.on("connection", function connection(ws, req) {
  ws.on("error", console.error);

  const parsedUrl = parse(req.url || " ", true);

  const token = parsedUrl.query.token as string;

  try {
    const userId = auth(token);
    if (!userId) {
      ws.send("Invalid token");
      ws.close();
      return;
    }
    users.push({
      userId,
      ws,
    });
  } catch (e) {
    console.error("JWT Verification Error: ", e);
    ws.send("Authentication failed");
    ws.close();
    return;
  }
  ws.send("Connected to ws server");

  ws.on("message", function message(data) {
    const message = data.toString();
    const parsedData = JSON.parse(message);

    if (parsedData.type === "join_room") {
      const user = users.find((x) => x.ws == ws);
      console.log(user);
      if (!user!.rooms) {
        user!.rooms = [];
      }
      if (!user?.rooms.includes(parsedData.roomId)) {
        user?.rooms?.push(parsedData.roomId);
      }
      console.log(user?.rooms);
      ws.send(`Joined Rooms: ${user?.rooms}`);
    } else if (parsedData.type === "chat") {
      const user = users.find((x) => x.ws == ws);
      const joinedRooms = user?.rooms;
      if (joinedRooms) {
        joinedRooms.forEach((room) => {
          users.forEach((u) => {
            if (u.rooms?.includes(room)) {
              u.ws.send(parsedData.message);
            }
          });
        });
      }
    } else {
      ws.send(`You sent ${message}`);
    }
  });
});
