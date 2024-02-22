import { Injectable, InternalServerErrorException } from '@nestjs/common';
import * as argon from 'argon2';

import { LoginResponseDto, LoginHandleDto } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { ITokenPayload } from './interfaces';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async login(loginDto: LoginHandleDto): Promise<LoginResponseDto> {
    let user = await this.prismaService.user.findUnique({
      where: {
        email: loginDto.email,
      },
    });

    // Create new user if not exists
    if (!user) {
      try {
        // Create new user
        user = await this.prismaService.user.create({
          data: {
            email: loginDto.email,
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
        refreshToken: hash,
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }
}
