import config from "nconf";
import { Schema, model, connect } from "mongoose";


interface IUser {
  _id?: string;
  loginName: string;
  fullName: string;
  email: string;
  enabled: boolean;
  password?: string;
  role: number;
}
interface IUpdateUser {
  loginName?: string;
  fullName?: string;
  email?: string;
  enabled?: boolean;
  password?: string;
  role?: number;
}
const userSchema = new Schema<IUser>({
  loginName: {type: String, required: true},
  fullName: {type: String, required: true},
  email: {type: String, required: true},
  enabled: {type: Boolean, required: true},
  password: String,
  role: {type: Number, required: true},
});
const UserModel = model<IUser>('User', userSchema);
const roles = {
  restricted: 1,
  viewer: 2,
  administrator: 3,
}

class Accounting{
  #dbUri = "";
  #error: string = "";
  constructor() {
    config.file("./config.json");
    const dbLogin = encodeURIComponent(config.get("database:login"));
    const dbPassword = encodeURIComponent(config.get("database:password"));
    const dbHost = config.get("database:host");
    const database = config.get("database:database");
    this.#dbUri = `mongodb://${dbLogin}:${dbPassword}@${dbHost}/${database}`;
    connect(this.#dbUri).catch(() => this.#error = "Could not connect to MongoDB.");
  }
  get error(){
    return this.#error;
  }
  async UserAdd(){
    const user  = new UserModel({
      loginName: "milokum.pavel",
      fullName: "Милокум Павел",
      email: "milokum.pavel@energospb.ru",
      role : roles.administrator,
      enabled : true,
    });
    await user.save();
  }
  async disableUser(userName:string){
    await this.#updateUser(userName,{enabled : false});
  }
  async enableUser(userName:string){
    await this.#updateUser(userName,{enabled : true});
  }
  async #updateUser(userName:string, update:IUpdateUser){
    this.#error = "";
    //const update = {enabled : false};
    try{
      await UserModel.findOneAndUpdate({loginName: userName}, update).exec();
    }catch (err){
      this.#error = "Could not connect to MongoDB.";
    }
  }
  async getUser(userName:string):Promise<( IUser & Required<{   _id: string }> & {   __v: number }) | null >{
    this.#error = "";
    let user: ( IUser & Required<{   _id: string }> & {   __v: number }) | null = null;
    try{
      user = await UserModel.findOne({loginName: userName}).exec();
    }catch (err){
      this.#error = "Could not connect to MongoDB.";
    }
    return user;
  }

  async getRole(userName:string):Promise<number>{
    const user:( IUser & Required<{   _id: string }> & {   __v: number }) | null  = await this.getUser(userName);
    if (user===null) {
      return roles.restricted;
    }
    return user.role;
  }

  async isUserEnabled(userName:string):Promise<boolean>{
    const user:( IUser & Required<{   _id: string }> & {   __v: number }) | null  = await this.getUser(userName);
    if (user===null) {
      return false;
    }
    return user.enabled;
  }

}

export const accounting = new Accounting();
