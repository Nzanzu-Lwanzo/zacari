import { applyDecorators } from '@nestjs/common';
import { ApiOperation } from '@nestjs/swagger';

export default {
  signUp: () =>
    applyDecorators(
      ApiOperation({
        summary: 'Sign up with Google',
      }),
    ),
  logIn: () =>
    applyDecorators(
      ApiOperation({
        summary: 'Log in with Google',
      }),
    ),
};
