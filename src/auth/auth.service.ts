import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon from 'argon2';

import { LoginResponseDto, LoginHandleDto, SignUpRequestDto } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { ITokenPayload } from './interfaces';
import { JwtService } from '@nestjs/jwt';
import { BasicLoginRequestDto } from './dto/basic-login-request.dto';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async basicLogin(loginDto: BasicLoginRequestDto): Promise<LoginResponseDto> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: loginDto.email,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Wrong email or password');
    }

    if (!user.password) {
      // User registered with Google
      throw new BadRequestException('Wrong email or password');
    }

    // Check password
    const passwordMatch = await argon.verify(user.password, loginDto.password);

    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong email or password');
    }

    // Generate tokens
    const tokens = await this.generateTokens({
      sub: user.id,
      email: user.email,
    });

    return {
      user: {
        email: user.email,
        name: user.name,
        image: user.image,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async googleLogin(loginDto: LoginHandleDto): Promise<LoginResponseDto> {
    let user = await this.prismaService.user.findUnique({
      where: {
        email: loginDto.email,
      },
    });

    // Create new user if not exists
    if (!user) {
      try {
        // Create new user (Google)
        user = await this.prismaService.user.create({
          data: {
            email: loginDto.email,
            password: null,
            name: loginDto.name,
            image: loginDto.image,
          },
        });
      } catch (err) {
        console.log('Error', err);
        throw new InternalServerErrorException('Error creating user');
      }
    }

    // Generate tokens
    const tokens = await this.generateTokens({
      sub: user.id,
      email: user.email,
    });

    return {
      user: {
        email: user.email,
        name: user.name,
        image: user.image,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async signUp(signUpDto: SignUpRequestDto): Promise<LoginResponseDto> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: signUpDto.email,
      },
    });

    if (user) {
      throw new BadRequestException('Email already in use');
    }

    const hash = await argon.hash(signUpDto.password);

    const newUser = await this.prismaService.user.create({
      data: {
        email: signUpDto.email,
        password: hash,
        name: signUpDto.name,
        image: null,
      },
    });

    // Generate tokens
    const tokens = await this.generateTokens({
      sub: newUser.id,
      email: newUser.email,
    });

    return {
      user: {
        email: newUser.email,
        name: newUser.name,
        image: newUser.image,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async getJwtAccessToken(sub: number, email: string): Promise<string> {
    const payload: ITokenPayload = { sub, email };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_AT_SECRET,
      expiresIn: process.env.JWT_AT_EXPIRES,
    });
    return accessToken;
  }

  async getJwtRefreshToken(sub: number, email: string): Promise<string> {
    const payload: ITokenPayload = { sub, email };
    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_RT_SECRET,
      expiresIn: process.env.JWT_RT_EXPIRES,
    });
    return refreshToken;
  }

  private async generateTokens(payload: ITokenPayload) {
    const accessToken = await this.getJwtAccessToken(
      payload.sub,
      payload.email,
    );

    const refreshToken = await this.getJwtRefreshToken(
      payload.sub,
      payload.email,
    );

    const hash = await argon.hash(refreshToken);

    await this.prismaService.user.update({
      where: {
        id: payload.sub,
      },
      data: {
        refresh_token: hash,
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }
}
