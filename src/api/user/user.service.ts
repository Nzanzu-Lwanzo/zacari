import { Injectable } from '@nestjs/common';
import { AuthProvider } from '@prisma/client';
import { CreateAccountDto } from 'src/auth/credential/dtos/create.dto';
import { CONFIRM_TOKEN_EXP, OTP_EXP } from 'src/lib/constants';
import { createInterval } from 'src/lib/datetime';
import { hashPwd } from 'src/lib/pwd';
import { PrismaService } from 'src/services/prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async getOAuthUser(provider: AuthProvider, providerID: string) {
    return await this.prisma.user.findFirst({
      where: {
        auth: {
          provider,
          providerID,
        },
      },
      select: {
        id: true,
        email: true,
        role: true,
      },
    });
  }

  async createOAuthUser(
    user: CreateAccountDto,
    provider: AuthProvider,
    providerID: string,
  ) {
    return this.prisma.user.create({
      data: {
        ...user,
        role: 'client',
        auth: {
          create: {
            provider,
            providerID,
            verified: true,
          },
        },
      },
      select: {
        id: true,
        email: true,
        role: true,
      },
    });
  }

  async saveOtp(uid: string, otp: string) {
    return await this.prisma.auth.update({
      where: {
        userID: uid,
      },
      data: {
        otp: await hashPwd(otp),
        otpExp: createInterval(`${OTP_EXP}m`),
      },
    });
  }

  async saveRt(uid: string, rt: string) {
    return await this.prisma.auth.update({
      where: {
        userID: uid,
      },
      data: {
        rt,
        rtExp: createInterval('30d'),
      },
    });
  }

  async saveConfirmToken(
    uid: string,
    { token, name }: { token: string; name: 'vt' | 'dt' },
  ) {
    let exp = `${name}Exp`; // rtExp or dtExp -> See database schema
    return await this.prisma.auth.update({
      where: {
        userID: uid,
      },
      data: {
        [name]: token,
        [exp]: createInterval(`${CONFIRM_TOKEN_EXP}m`),
      },
    });
  }
}
