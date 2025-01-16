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
  UNAUTHORIZED: 401,
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
      process.exit(1);
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
  setError(res:Response,status:number){
    res.status(status).json({
      success: false,
    });
  }
  async setAccessTokenResponse(res:Response, loginName:string){
    let accessToken = "";
    try{
      const role = await accounting.getRole(loginName);
      accessToken = authorization.getAccessToken(loginName, role);
    }catch (err){
      this.setError(res,HTTP_STATUS.INTERNAL_SERVER_ERROR);
      return;
    }
    res.json({
      success: true,
      token: accessToken,
    });
  }
  async validateUserAndGenerateResponse(res:Response, loginName: string, oldRefreshToken:string){
    const enabled = await accounting.isUserEnabled(loginName);
    if (enabled){
      if (!oldRefreshToken){
        const refreshToken = this.getRefreshToken(loginName);
        res.cookie("refreshToken", refreshToken);
      }
      await this.setAccessTokenResponse(res,loginName);

    }else{
      res.clearCookie("refreshToken");
      this.setError(res,HTTP_STATUS.FORBIDDEN);
    }
  }
  async authorize(req: Request, res: Response) {
    let loginName = "";
    let refreshToken = req.cookies["refreshToken"];
    if (refreshToken) {
      loginName = this.verifyRefreshToken(refreshToken)
      if (loginName){
        await this.validateUserAndGenerateResponse(res,loginName, refreshToken);
        return;
      }
    }
    const ssoUser = req.sso?.user;
    if (!ssoUser?.name) {
      this.setError(res, HTTP_STATUS.INTERNAL_SERVER_ERROR);
      return;
    }
    loginName = ssoUser.name;
    await this.validateUserAndGenerateResponse(res, loginName, "");
  }
}

export const authorization = new Authorization();
