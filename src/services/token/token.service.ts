import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomInt, randomUUID } from 'node:crypto';
import { AT_AUD, RT_AUD, TEMP_AT_AUD } from 'src/lib/constants';
import { getCrypt } from 'src/lib/crypting';
import { PayloadType } from 'src/lib/global.types';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async getTempAt(payload: PayloadType) {
    return await this.jwt.signAsync(payload, {
      secret: this.config.getOrThrow('jwt.tempAtSecret'),
      expiresIn: parseInt(this.config.getOrThrow('jwt.tempAtExp')),
      audience: TEMP_AT_AUD,
    });
  }

  async getRt(payload: PayloadType) {
    return await this.jwt.signAsync(payload, {
      secret: this.config.getOrThrow('jwt.rtSecret'),
      expiresIn: parseInt(this.config.getOrThrow('jwt.rtExp')),
      audience: RT_AUD,
    });
  }

  async getAt(payload: PayloadType) {
    return await this.jwt.signAsync(payload, {
      secret: this.config.getOrThrow('jwt.atSecret'),
      expiresIn: parseInt(this.config.getOrThrow('jwt.atExp')),
      audience: AT_AUD,
    });
  }

  async getAuthTokens(payload: PayloadType) {
    const rt = await this.getRt(payload);
    const at = await this.getAt(payload);
    return { rt, at };
  }

  get confirmationToken() {
    const id = randomUUID();
    const token = getCrypt(id);
    return token;
  }

  get OTP() {
    const code = randomInt(100000, 1000000);
    return code.toString();
  }
}
