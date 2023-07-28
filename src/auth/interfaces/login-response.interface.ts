import { User } from "../entities/user.entity";

export interface LoginResponse {
  info: User;
  jwt: string;
}