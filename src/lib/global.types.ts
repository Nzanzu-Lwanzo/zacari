import { Role } from '@prisma/client';

export interface PayloadType {
  id: string;
  email: string;
  role: Role;
}

export interface User extends PayloadType {
  iat: number;
  exp: number;
  aud: string;
}
