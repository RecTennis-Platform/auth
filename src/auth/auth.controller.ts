import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { GoogleLoginRequestDto } from './dto';

import { OAuth2Client } from 'google-auth-library';

const client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
);

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(200)
  @Post('/login/google')
  async googleLogin(@Body() dto: GoogleLoginRequestDto): Promise<any> {
    const ticket = await client.verifyIdToken({
      idToken: dto.token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    // console.log(ticket.getPayload(), 'ticket');

    const { email, name, picture } = ticket.getPayload();
    const data = await this.authService.login({ email, name, image: picture });

    return {
      data,
    };
  }

  @Post('/login/facebook')
  async FacebookLogin() {
    return 'Facebook login';
  }

  @Post('/login/basic')
  async BasicLogin() {
    return 'Basic login';
  }
}
