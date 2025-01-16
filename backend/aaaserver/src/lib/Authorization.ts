import fs from "node:fs";
import jwt from "jsonwebtoken";
import { Request, Response } from 'express';
import {accounting} from "./Accounting";
import config from "nconf";

interface AccessTokenPayload {
  name: string;
  role: number;
}

interface RefreshTokenPayload {
  loginName: string;
}

const HTTP_STATUS = {
  FORBIDDEN: 403,
  INTERNAL_SERVER_ERROR: 500,
};

class Authorization {
  #accessTokenPrivateKey = "";
  #accessTokenPublicKey = "";
  #refreshTokenPrivateKey = "";
  #refreshTokenPublicKey = "";
  #accessTokenExpiresInSec = 600;
  constructor() {
    config.file("./config.json");
    this.#accessTokenExpiresInSec = config.get("jwt:accessTokenExpiresInSec");
    try{
      this.#accessTokenPrivateKey = fs.readFileSync(config.get("jwt:accessTokenPrivateKeyFileName"), "utf8");
      this.#accessTokenPublicKey = fs.readFileSync(config.get("jwt:accessTokenPublicKeyFileName"), "utf8");
      this.#refreshTokenPrivateKey = fs.readFileSync(config.get("jwt:refreshTokenPrivateKeyFileName"), "utf8");
      this.#refreshTokenPublicKey = fs.readFileSync(config.get("jwt:refreshTokenPublicKeyFileName"), "utf8");
    }catch (err) {
      console.log("Cannot read keys.");
    }
  }
  getAccessToken(name:string, role:number){
    const payload:AccessTokenPayload = { name , role};
    return  jwt.sign(payload, this.#accessTokenPrivateKey,
      { expiresIn: this.#accessTokenExpiresInSec,  algorithm: "ES256" }
    );
  }
  getRefreshToken(name:string){
    const payload :RefreshTokenPayload= { loginName: name };
    return  jwt.sign(payload, this.#refreshTokenPrivateKey,
      {  algorithm: "ES512" }
    );
  }
  verifyRefreshToken(refreshToken:string):string{
    try {
      const payload = jwt.verify(refreshToken, this.#refreshTokenPublicKey) as RefreshTokenPayload;
      if (typeof payload === "object" && payload !== null) {
        if ("loginName" in payload) {
          return payload.loginName;
        }
      }
    }
    catch (err){
      console.log("Refresh token verify failed ");
    }
    return "";
  }
  setError403(res:Response){
    res.status(HTTP_STATUS.FORBIDDEN).json({
      success: false,
    });
  }
  setError500(res:Response){
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      success: false,
    });
  }
  async setAccessTokenResponse(res:Response, loginName:string){
    const role = await accounting.getRole(loginName);
    const accessToken = authorization.getAccessToken(loginName, role);
    res.json({
      success: true,
      token: accessToken,
    });
  }
  async authorize(req: Request, res: Response) {
    let loginName = "";
    let refreshToken = req.cookies["refreshToken"];
    if (refreshToken) {
      loginName = this.verifyRefreshToken(refreshToken)
      if (loginName){
        const enabled = await accounting.isUserEnabled(loginName);
        if (enabled){
          await this.setAccessTokenResponse(res,loginName);
          return;
        }
        res.clearCookie("refreshToken");
        this.setError403(res);
        return;
      }
    }
    if ((req.sso.user === undefined) || (req.sso.user.name === undefined)) {
      this.setError500(res);
      return;
    }
    loginName = req.sso.user.name;
    const enabled = await accounting.isUserEnabled(loginName);
    if (enabled){
      const refreshToken = this.getRefreshToken(loginName);
      res.cookie("refreshToken", refreshToken);
      await this.setAccessTokenResponse(res,loginName);
      return;
    }
    this.setError403(res);
  }
}

export const authorization = new Authorization();
