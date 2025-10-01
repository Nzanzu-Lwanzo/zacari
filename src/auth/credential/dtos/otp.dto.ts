import { IsNotEmpty, IsString, MaxLength } from 'class-validator';

export class ValidateOtpDto {
  @IsString({ message: 'code must be a string' })
  @MaxLength(6, { message: 'code max length is 6' })
  @IsNotEmpty({ message: 'code cannot be empty' })
  code: string;
}
