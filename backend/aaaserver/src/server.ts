import express from "express";
import { Request, Response } from 'express';
import { sso } from "node-expose-sspi";

const app = express();
app.use(sso.auth());
const port = 3000;

app.get('/', (req: Request, res: Response) => {
  //res.send('Hello, TypeScript with Express!');
  res.json({
    sso: req.sso
  });
});

app.listen(port, () => {
  console.log(`Server is running at <http://localhost>:${port}`);
});
