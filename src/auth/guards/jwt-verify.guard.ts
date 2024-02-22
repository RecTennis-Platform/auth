import { AuthGuard } from '@nestjs/passport';

export class JwtVerifyGuard extends AuthGuard('jwt-verify') {
  constructor() {
    super();
  }
}
