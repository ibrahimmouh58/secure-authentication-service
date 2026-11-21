declare global {
  namespace Express {
    interface Request {
      auth?: {
        userId: string;
        sessionId: string;
        email: string;
        role: "USER" | "ADMIN";
      };
    }
  }
}

export {};