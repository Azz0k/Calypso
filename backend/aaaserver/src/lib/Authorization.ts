import fs from "node:fs";
import jwt from "jsonwebtoken";
import { Request, Response } from 'express';
import {accounting} from "./Accounting";

class Authorization {
  #error = "";
  #privateKey = "";
  //#publicKey = "";
  #accounting = accounting;
  constructor() {
    try{
      this.#privateKey = fs.readFileSync("./private.key", "utf8");
    }catch (err) {
      this.#error = "Cannot read private key.";
    }
  }
  get error(){
    return this.#error;
  }
  token(name:string, role:number){
    const payload = { name , role};
    return  jwt.sign(payload, this.#privateKey, { expiresIn: 600,  algorithm: "ES256" });
  }
  async authorize(req: Request, res: Response) {
    //await accounting.enableUser("milokum.pavel");
    let role:number = parseInt(req.cookies["role"]);
    let name = req.cookies["loginName"];
    let isSuccess = true;
    let errorMessages: string[] = [];
    if (isNaN(role)){
      if ((req.sso.user !== undefined) && (req.sso.user.name !== undefined)) {
        name = req.sso.user.name;
      } else {
        isSuccess = false;
        errorMessages.push("Authentication failed");
      }
      role = await accounting.getRole(name);
    }
    const enabled = await accounting.isUserEnabled(name);
    if (!enabled || !isSuccess){
      errorMessages.push("You are not allowed to access");
      res.clearCookie("loginName");
      res.clearCookie("role");
      res.json({
        success: false,
        errorMessages: errorMessages,
      });
      return;
    }
    const token = authorization.token(name, role);
    if (authorization.error) {
      isSuccess = false;
      errorMessages.push(authorization.error);
    }
    res.cookie("loginName", name, { httpOnly: true });
    res.cookie("role", role, { httpOnly: true });
    res.json({
      success: isSuccess,
      token: token,
      errorMessages: errorMessages,
    });
  }

}

export const authorization = new Authorization();
