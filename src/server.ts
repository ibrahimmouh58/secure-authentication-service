import "dotenv/config";
import { app } from "./app";

const PORT = Number(process.env.PORT ?? 7766);
app.listen(PORT, () => console.log(`API listening on port ${PORT}`));