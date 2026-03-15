import express from "express";
import { basicAuth } from "./middleware/basicAuth";

const app = express();

app.get("/protected", basicAuth, (req, res) => {
  res.json({
    message: "Access granted",
    user: res.locals.user,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
