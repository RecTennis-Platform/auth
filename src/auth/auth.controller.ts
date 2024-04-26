import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  ChangePasswordDto,
  // ForgotPasswordDto,
  GoogleLoginRequestDto,
  LoginResponseDto,
  // ResetPasswordDto,
  SignUpRequestDto,
} from './dto';

import { OAuth2Client } from 'google-auth-library';
import { BasicLoginRequestDto } from './dto/basic-login-request.dto';
import {
  JwtGuard,
  JwtRefreshGuard,
  // JwtVerifyGuard,
} from './guards';
import { IRequestWithUser } from './interfaces';

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
    try {
      const ticket = await client.verifyIdToken({
        idToken: dto.token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });

      console.log(ticket.getPayload());
      const { email, name, picture } = ticket.getPayload();
      return await this.authService.googleLogin({
        email,
        name,
        image: picture,
      });
    } catch (error) {
      console.log('Error:', error.message);
      throw new BadRequestException('Invalid token');
    }
  }

  @Post('signup')
  async signUp(@Body() dto: SignUpRequestDto) {
    return await this.authService.signUp(dto);
  }

  @UseGuards(JwtGuard)
  @Post('logout')
  @HttpCode(200)
  async signOut(@Req() req: IRequestWithUser) {
    const userId = req.user['sub'];
    return await this.authService.logOut(userId);
  }

  @UseGuards(JwtRefreshGuard)
  @HttpCode(200)
  @Post('refresh')
  async refresh(@Req() req: IRequestWithUser) {
    const refreshToken = req.user['refreshToken'];
    const payload = req.user['payload'];
    return await this.authService.refresh(refreshToken, payload);
  }

  @UseGuards(JwtGuard)
  @HttpCode(200)
  @Post('change-password')
  async changePassword(
    @Req() req: IRequestWithUser,
    @Body() dto: ChangePasswordDto,
  ) {
    const userId = req.user['sub'];
    return await this.authService.changePassword(userId, dto);
  }

  // @HttpCode(200)
  // @Post('forgot-password')
  // async forgotPassword(@Body() dto: ForgotPasswordDto) {
  //   const email = dto.email;
  //   return await this.authService.forgotPassword(email);
  // }

  // @UseGuards(JwtVerifyGuard)
  // @HttpCode(200)
  // @Post('reset-password')
  // async resetPassword(
  //   @Req() req: IRequestWithUser,
  //   @Body() dto: ResetPasswordDto,
  // ) {
  //   const payload = req.user['payload'];
  //   return await this.authService.resetPassword(
  //     payload['sub'],
  //     dto.newPassword,
  //   );
  // }
}
