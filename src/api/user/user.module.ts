import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { PrismaModule } from 'src/services/prisma/prisma.module';

@Module({
  controllers: [],
  providers: [UserService],
  exports: [UserService],
  imports: [PrismaModule],
})
export class UserModule {}
