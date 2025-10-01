import { Injectable, ValidationPipe } from '@nestjs/common';

@Injectable()
export class ValidateDtoPipe extends ValidationPipe {
  constructor() {
    super({
      forbidNonWhitelisted: true,
      whitelist: true,
    });
  }
}
