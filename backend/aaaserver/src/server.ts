import express from "express";
import { sso } from "node-expose-sspi";
import {authorization} from "./lib/Authorization";
import cookieParser from "cookie-parser";

const app = express();
app.use(cookieParser());
app.use(sso.auth());
const port = 3000;

app.get("/", authorization.authorize);

app.listen(port, () => {
  console.log(`Server is running at http://localhost>:${port}`);
});
