import {
  IsEmail,
  IsNotEmpty,
  IsPhoneNumber,
  IsString,
  IsStrongPassword,
  MaxLength,
} from 'class-validator';

const strongPwdOptions = {
  minLowercase: 2,
  minNumbers: 2,
  minSymbols: 2,
  minUppercase: 2,
};

export class CreateAccountDto {
  @IsString({ message: 'name must be a string' })
  @MaxLength(64, { message: 'name max length is 64' })
  @IsNotEmpty({ message: 'name cannot be empty' })
  name: string;

  @IsEmail(undefined, { message: 'email must be an email' })
  @IsNotEmpty({ message: 'email cannot be empty' })
  email: string;

  @IsPhoneNumber(undefined, { message: 'phone must be a phone number' })
  @IsNotEmpty({ message: 'phone cannot be empty' })
  phone: string;

  @IsString({ message: 'password must be a string' })
  @IsStrongPassword(strongPwdOptions, {
    message: 'password must be strong password',
  })
  @IsNotEmpty({ message: 'password cannot be empty' })
  password: string;
}
