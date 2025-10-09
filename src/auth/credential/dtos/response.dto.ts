import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { USER_ROLES_ENUM_ARR } from 'src/lib/constants';

export class UserResDto {
  id: string;
  name: string;
  email: string;
  @ApiProperty({ enum: USER_ROLES_ENUM_ARR })
  role: Role;
}

export class TokensResDto {
  at: string;
  rt: string;
}

export class UserWithTokensResDto extends TokensResDto {
  user: UserResDto;
}
