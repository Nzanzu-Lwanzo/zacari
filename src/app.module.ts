import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { CredentialModule } from './auth/credential/credential.module';
import { PrismaModule } from './services/prisma/prisma.module';
import { TokenModule } from './services/token/token.module';
import { ContactModule } from './services/contact/contact.module';
import { ConfigModule } from '@nestjs/config';
import jwtConfig from './lib/config/jwt.config';
import { JwtModule } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import { AccessTokenGuard } from './auth/credential/common/guards/access-token.guard';
import { GoogleModule } from './auth/google/google.module';
import { UserModule } from './api/user/user.module';
import googleConfig from './lib/config/google.config';

@Module({
  imports: [
    CredentialModule,
    PrismaModule,
    TokenModule,
    ContactModule,
    ConfigModule.forRoot({
      cache: true,
      isGlobal: true,
      load: [jwtConfig, googleConfig],
    }),
    JwtModule.register({
      global: true,
      secret: process.env.JWT_DEFAULT_SECRET,
    }),
    GoogleModule,
    UserModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AccessTokenGuard, // Global check the presence of access token
    },
    AppService,
  ],
})
export class AppModule {}
