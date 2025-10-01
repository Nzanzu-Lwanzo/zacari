import { Injectable } from '@nestjs/common';
import { ConfirmOptionsType } from 'src/auth/credential/lib/@types';
import { API_ORIGIN, CONFIRM_TOKEN_EXP, OTP_EXP } from 'src/lib/constants';

@Injectable()
export class ContactService {
  async sendSMS(phone: string, mail: string) {
    return true;
  }

  async sendEmail(email: string, mail: string) {
    return true;
  }

  formatConfirmEmail(action: ConfirmOptionsType, token: string) {
    return `
      Hi there ! Seems like you need to confirm an account ${action}.\n

      Please, click on the following link :
      ${API_ORIGIN}/confirm?token=${token}&action=${action}\n

      Something we gotta tell you :
      - Use the link within ${CONFIRM_TOKEN_EXP} minutes.
      - Do not reply in any case.
      - Ignore this email if it wasn't you.
    `;
  }

  formatOTPMessage(otp: string) {
    return `
      Hi there ! Here's your OTP code. Keep it safe and secret !\n
      ${otp}\n
      Caution : The OTP expires within ${OTP_EXP} minutes.
    `;
  }

  formatOTPEmail(otp: string) {
    return `
      Hi there ! Here's your OTP code. Keep it safe and secret !\n
      ${otp}\n
      Caution : The OTP expires within ${OTP_EXP} minutes.
    `;
  }
}
