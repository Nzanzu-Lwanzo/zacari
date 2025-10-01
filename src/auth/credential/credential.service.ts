import {
  Injectable,
  NotFoundException,
  PreconditionFailedException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateAccountDto } from './dtos/create.dto';
import { PrismaService } from 'src/services/prisma/prisma.service';
import { checkPwdMatch, hashPwd } from 'src/lib/pwd';
import { TokenService } from 'src/services/token/token.service';
import {
  createInterval,
  currentTimeStamp,
  isExpired,
  minutesSince,
} from 'src/lib/datetime';
import { ContactService } from 'src/services/contact/contact.service';
import { selectAuthUser } from './lib/projection';
import { CredentialsDto } from './dtos/credentials.dto';
import {
  TIME_BEFORE_NEXT_LOGIN,
  MAX_LOGIN_ATTEMPTS,
  CONFIRM_TOKEN_EXP,
  OTP_EXP,
} from 'src/lib/constants';
import { TEMP_AT_EXP } from '../../lib/constants';
import { ValidateOtpDto } from './dtos/otp.dto';
import { User } from 'src/lib/global.types';
import { Auth, AuthProvider } from '@prisma/client';
import {
  ConfirmOptionsType,
  ResendOptionsType,
  sendSMSMediumType,
} from './lib/@types';
import { UpdateCredentialsDto } from './dtos/update.dto';

@Injectable()
export class CredentialService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly token_service: TokenService,
    private readonly contact_service: ContactService,
  ) {}

  async createAccount(dto: CreateAccountDto) {
    let token = this.token_service.confirmationToken;
    let mailText = this.contact_service.formatConfirmEmail('creation', token);
    return await this.contact_service
      .sendEmail(dto.email, mailText)
      .then((sent) => {
        return (
          sent ||
          (() => {
            throw new PreconditionFailedException(
              "Couldn't send the confirmation email",
            );
          })()
        );
      })
      .then(async () => {
        return await this.prisma.user.create({
          data: {
            ...dto,
            password: await hashPwd(dto.password),
            auth: {
              create: {
                provider: AuthProvider.credentials,
                vt: token,
                vtExp: createInterval(`${TEMP_AT_EXP}m`),
              },
            },
          },
          select: selectAuthUser,
        });
      })
      .then(async (account) => {
        const temp_at = await this.token_service.getTempAt({
          id: account.id,
          email: account.email,
          role: account.role,
        });
        return { vt: token, at: temp_at };
      });
  }

  async confirmAccountCreation(token: string) {
    return await this.prisma.user
      .findFirst({
        where: {
          auth: {
            vt: token,
          },
        },
        include: {
          auth: {
            select: {
              vtExp: true,
            },
          },
        },
      })
      .then(async (account) => {
        if (!account || !account.auth || !account.auth.vtExp) {
          throw new NotFoundException('Account not found, invalid token');
        }
        const expired = isExpired(account.auth?.vtExp);
        if (expired) {
          throw new UnauthorizedException(
            'Token expired, request a new confirmation email',
          );
        }
        return account;
      })
      .then(async (account) => {
        return await this.prisma.user.update({
          where: {
            id: account.id,
          },
          data: {
            auth: {
              update: {
                vt: { set: null },
                vtExp: { set: null },
                verified: true,
              },
            },
          },
          select: selectAuthUser,
        });
      });
  }

  async logIn(dto: CredentialsDto, ip: string) {
    return await this.prisma.user
      .findUnique({
        where: {
          email: dto.email,
        },
        select: {
          id: true,
          email: true,
          role: true,
          phone: true,
          password: true,
          auth: {
            select: {
              id: true,
              verified: true,
              locked: true,
            },
          },
        },
      })
      .then((user) => {
        return (
          user ||
          (() => {
            throw new NotFoundException('User not found');
          })()
        );
      })
      .then(({ auth, ...user }) => {
        if (auth?.locked) throw new UnauthorizedException('Account locked');
        if (!auth?.verified)
          throw new UnauthorizedException('Account not confirmed');
        return { user, authID: auth.id };
      })
      .then(async ({ user: { password, ...user }, authID }) => {
        const match = await checkPwdMatch(password, dto.password);
        if (!match) await this.handleFailedAuthAttempt(authID, ip);
        return user;
      })
      .then(async ({ phone, ...user }) => {
        const otp = this.token_service.OTP;
        const message = this.contact_service.formatOTPMessage(otp);
        const sent = await this.contact_service.sendSMS(phone, message);
        if (!sent) {
          throw new PreconditionFailedException("Couldn't send the OTP code");
        }
        return { user, otp };
      })
      .then(async ({ user, otp }) => {
        await this.saveOtpOnUser(user.id, otp);
        // Generate a short-living token
        const temp_at = await this.token_service.getTempAt({
          id: user.id,
          email: user.email,
          role: user.role,
        });

        return { at: temp_at, otp };
      });
  }

  async validateOTP(dto: ValidateOtpDto, user: User, ip: string) {
    return await this.prisma.user
      .findUnique({
        where: {
          email: user.email,
        },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          auth: {
            select: {
              id: true,
              otp: true,
              otpExp: true,
              locked: true,
            },
          },
        },
      })
      .then((user) => {
        if (!user || !user.auth) throw new NotFoundException('User not found');
        if (!user.auth?.otp) throw new UnauthorizedException('No OTP saved');
        return user;
      })
      .then(async (user) => {
        const match = await checkPwdMatch(user.auth?.otp!, dto.code);
        if (!match) await this.handleFailedAuthAttempt(user.auth?.id!, ip);
        return user;
      })
      .then(async ({ auth, ...user }) => {
        await this.prisma.auth.update({
          where: {
            id: auth?.id,
          },
          data: {
            lastLoginDate: currentTimeStamp(),
            lastLoginIp: ip,
            otp: { set: null },
            otpExp: { set: null },
          },
        });
        return user;
      })
      .then(async (user) => {
        const { at, rt } = await this.token_service.getAuthTokens({
          id: user.id,
          email: user.email,
          role: user.role,
        });
        await this.saveRtOnUser(user.id, rt);
        await this.resetLoginAttempts(user.id);
        return { user, at, rt };
      });
  }

  async resend(
    what: ResendOptionsType,
    user: User,
    action: ConfirmOptionsType,
  ) {
    switch (what) {
      case 'otp': {
        // Look up user in the db
        let account = await this.prisma.user.findUnique({
          where: { email: user.email },
          select: {
            phone: true,
          },
        });
        if (!account) throw new NotFoundException('User not found');

        // Generate, send and new OTP
        let otp = this.token_service.OTP;
        let message = this.contact_service.formatOTPMessage(otp);
        let sent = await this.contact_service.sendSMS(account.phone, message);
        if (!sent) throw new PreconditionFailedException("Couldn't send OTP");
        await this.saveOtpOnUser(user.id, otp);

        // Generate and return temporary access token
        const temp_at = await this.token_service.getTempAt({
          id: user.id,
          email: user.email,
          role: user.role,
        });
        return { at: temp_at, otp };
      }

      case 'confirm': {
        let token = this.token_service.confirmationToken;
        let mailText = this.contact_service.formatConfirmEmail(action, token);
        let sent = await this.contact_service.sendEmail(user.email, mailText);
        if (!sent) throw new PreconditionFailedException("Couldn't sent token");
        await this.saveTokenOnUser(user.id, { token, name: 'vt' });
        let temp_at = await this.token_service.getTempAt({
          id: user.id,
          email: user.email,
          role: user.role,
        });
        return { at: temp_at, vt: token };
      }
    }
  }

  async logOut(user: User) {
    return await this.prisma.auth.update({
      where: {
        userID: user.id,
      },
      data: {
        vt: { set: null },
        vtExp: { set: null },
      },
      select: {
        id: true,
      },
    });
  }

  async refresh(user: User) {
    const { at, rt } = await this.token_service.getAuthTokens({
      id: user.id,
      email: user.email,
      role: user.role,
    });
    await this.saveRtOnUser(user.id, rt);
    return { at, rt };
  }

  async deleteAccount(user: User) {
    let token = this.token_service.confirmationToken;
    let mailText = this.contact_service.formatConfirmEmail('deletion', token);
    return await this.contact_service
      .sendEmail(user.email, mailText)
      .then((sent) => {
        return (
          sent ||
          (() => {
            throw new PreconditionFailedException(
              "Couldn't send the confirmation email",
            );
          })()
        );
      })
      .then(async () => {
        await this.saveTokenOnUser(user.id, { token, name: 'dt' });
        let temp_at = await this.token_service.getTempAt({
          id: user.id,
          email: user.email,
          role: user.role,
        });
        return { dt: token, at: temp_at };
      });
  }

  async confirmAccountDeletion(token: string) {
    const auth = await this.prisma.auth.findFirst({ where: { dt: token } });
    if (!auth) throw new NotFoundException('Account not found, invalid token');
    let expired = isExpired(auth.vtExp!);
    if (!expired) throw new UnauthorizedException('Token expired');
    return await this.prisma.user.delete({
      where: { id: auth.userID },
      select: selectAuthUser,
    });
  }

  async initUpdate(send_otp_medium: sendSMSMediumType, user: User) {
    let otp = this.token_service.OTP;
    return this.prisma.user
      .findUnique({
        where: { id: user.id },
        select: { phone: true },
      })
      .then((_user) => {
        return (
          _user ||
          (() => {
            throw new UnauthorizedException('User not found');
          })()
        );
      })
      .then(async (_user) => {
        switch (send_otp_medium) {
          case 'email': {
            let mailText = this.contact_service.formatOTPEmail(otp);
            return await this.contact_service.sendEmail(user.email, mailText);
          }

          case 'sms': {
            let message = this.contact_service.formatOTPMessage(otp);
            return await this.contact_service.sendSMS(_user.phone, message);
          }
        }
      })
      .then((sent) => {
        return (
          sent ||
          (() => {
            throw new PreconditionFailedException(
              `Couldn't send the OTP ${send_otp_medium}`,
            );
          })()
        );
      })
      .then(async () => {
        await this.saveOtpOnUser(user.id, otp);
        let temp_at = await this.token_service.getTempAt({
          id: user.id,
          email: user.email,
          role: user.role,
        });
        return { at: temp_at, otp };
      });
  }

  async handleFailedAuthAttempt(authID: string, ip: string) {
    // Update information about login
    let { failedLoginAttempts, failedLoginDate, failedLoginIp } =
      await this.updateUserOnFailedAuth(authID, ip);

    // Check if account is to be locked
    let lock = this.isAccountToLock({
      failedLoginAttempts,
      failedLoginDate,
      failedLoginIp,
      ip,
    });

    return lock
      ? (async () => {
          await this.lockAccount(authID);
          throw new UnauthorizedException('Account got locked');
        })()
      : (() => {
          throw new UnauthorizedException('Login failed');
        })();
  }

  async completeUpdate(dto: UpdateCredentialsDto, user: User) {
    return await this.prisma.auth
      .findUnique({
        where: {
          userID: user.id,
        },
        select: {
          otp: true,
          otpExp: true,
        },
      })
      .then((auth) => {
        if (!auth) {
          throw new NotFoundException('Account not found');
        }
        return auth;
      })
      .then(async (auth) => {
        let match = await checkPwdMatch(auth.otp!, dto.otp);
        if (!match) throw new UnauthorizedException('Invalid OTP');
        let expired = isExpired(auth.otpExp!);
        if (expired) throw new UnauthorizedException('Expired OTP');
        return;
      })
      .then(async () => {
        return this.prisma.user.update({
          where: {
            id: user.id,
          },
          data: {
            email: dto.email,
            password: dto.password ? await hashPwd(dto.password) : undefined,
          },
          select: selectAuthUser,
        });
      })
      .then(async (user) => {
        const { at, rt } = await this.token_service.getAuthTokens({
          id: user.id,
          email: user.email,
          role: user.role,
        });
        await this.saveRtOnUser(user.id, rt);
        return { user, at, rt };
      });
  }

  async updateUserOnFailedAuth(authID: string, ip: string) {
    return await this.prisma.auth.update({
      where: {
        id: authID,
      },
      data: {
        failedLoginDate: currentTimeStamp(),
        failedLoginIp: ip,
        failedLoginAttempts: {
          increment: 1,
        },
      },
    });
  }

  async lockAccount(authID: string) {
    await this.prisma.auth.update({
      where: {
        id: authID,
      },
      data: {
        verified: { set: false },
        failedLoginDate: currentTimeStamp(),
        locked: true,
      },
    });
  }

  async saveOtpOnUser(uid: string, otp: string) {
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

  async saveRtOnUser(uid: string, rt: string) {
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

  async saveTokenOnUser(
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

  async resetLoginAttempts(uid: string) {
    return await this.prisma.auth.update({
      where: {
        userID: uid,
      },
      data: {
        failedLoginAttempts: { set: 0 },
      },
    });
  }

  isAccountToLock({
    failedLoginDate,
    failedLoginIp,
    failedLoginAttempts,
    ip,
  }: Pick<Auth, 'failedLoginAttempts' | 'failedLoginDate' | 'failedLoginIp'> & {
    ip: string;
  }) {
    let sameIP = failedLoginIp === ip;
    let quick = minutesSince(failedLoginDate!) < TIME_BEFORE_NEXT_LOGIN;
    let lotsOfAttempts = failedLoginAttempts >= MAX_LOGIN_ATTEMPTS;
    return sameIP && quick && lotsOfAttempts;
  }
}
