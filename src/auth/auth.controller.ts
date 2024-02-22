import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  GoogleLoginRequestDto,
  LoginResponseDto,
  SignUpRequestDto,
} from './dto';

import { OAuth2Client } from 'google-auth-library';
import { BasicLoginRequestDto } from './dto/basic-login-request.dto';

const client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
);

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(200)
  @Post('login')
  async basicLogin(@Body() dto: BasicLoginRequestDto) {
    return await this.authService.basicLogin(dto);
  }

  @HttpCode(200)
  @Post('login/google')
  async googleLogin(
    @Body() dto: GoogleLoginRequestDto,
  ): Promise<LoginResponseDto> {
    const ticket = await client.verifyIdToken({
      idToken: dto.token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const { email, name, picture } = ticket.getPayload();
    return await this.authService.googleLogin({ email, name, image: picture });
  }

  @Post('signup')
  async signUp(@Body() dto: SignUpRequestDto) {
    return await this.authService.signUp(dto);
  }
}
