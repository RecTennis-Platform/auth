import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon from 'argon2';

import {
  LoginResponseDto,
  LoginHandleDto,
  SignUpRequestDto,
  ChangePasswordDto,
} from './dto';
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
    const user = await this.prismaService.users.findUnique({
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
      role: user.role,
    });

    return {
      user: {
        email: user.email,
        name: user.name,
        image: user.image,
        role: user.role,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async googleLogin(loginDto: LoginHandleDto): Promise<LoginResponseDto> {
    let user = await this.prismaService.users.findUnique({
      where: {
        email: loginDto.email,
      },
    });

    // Create new user if not exists
    if (!user) {
      try {
        // Create new user (Google)
        user = await this.prismaService.users.create({
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
      role: user.role,
    });

    return {
      user: {
        email: user.email,
        name: user.name,
        image: user.image,
        role: user.role,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async signUp(signUpDto: SignUpRequestDto): Promise<LoginResponseDto> {
    const user = await this.prismaService.users.findUnique({
      where: {
        email: signUpDto.email,
      },
    });

    if (user) {
      throw new BadRequestException('Email already in use');
    }

    const hash = await argon.hash(signUpDto.password);

    const newUser = await this.prismaService.users.create({
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
      role: newUser.role,
    });

    return {
      user: {
        email: newUser.email,
        name: newUser.name,
        image: newUser.image,
        role: newUser.role,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async logOut(userId: number): Promise<{
    msg: string;
    data: any;
  }> {
    const user = await this.prismaService.users.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Check if user is already logged out
    if (!user.refreshToken) {
      throw new UnauthorizedException('Unauthorized');
    }

    try {
      // Update user's refresh token to null
      await this.prismaService.users.update({
        where: {
          id: userId,
        },
        data: {
          refreshToken: null,
        },
      });

      return {
        msg: 'success',
        data: null,
      };
    } catch (err) {
      console.log('Error:', err);
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async refresh(refreshToken: string, payload: ITokenPayload) {
    const user = await this.prismaService.users.findUnique({
      where: {
        id: payload.sub,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Unauthorized');
    }

    // Check if user is already logged out
    if (!user.refreshToken) {
      throw new UnauthorizedException('Unauthorized');
    }

    // Compare refresh token
    const isMatch = await argon.verify(user.refreshToken, refreshToken);

    if (!isMatch) {
      throw new UnauthorizedException('Unauthorized');
    }

    return await this.generateTokens(payload);
  }

  async changePassword(
    userId: number,
    dto: ChangePasswordDto,
  ): Promise<{
    msg: string;
    data: any;
  }> {
    // Find user
    const user = await this.prismaService.users.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Unauthorized');
    }

    // Check if old password is the same as new password
    if (dto.oldPassword === dto.newPassword) {
      throw new BadRequestException(
        'New password must be different from old password',
      );
    }

    // Check old password
    const isMatch = await argon.verify(user.password, dto.oldPassword);
    if (!isMatch) {
      throw new UnauthorizedException('Old password is incorrect');
    }

    // Hash new password
    const hash = await argon.hash(dto.newPassword);

    // Update user password
    try {
      await this.prismaService.users.update({
        where: {
          id: userId,
        },
        data: {
          password: hash,
        },
      });

      return {
        msg: 'success',
        data: null,
      };
    } catch (err) {
      console.log('Error:', err);
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  // async forgotPassword(email: string) {
  //   // Find user
  //   const user = await this.prismaService.users.findUnique({
  //     where: {
  //       email,
  //     },
  //   });

  //   if (!user) {
  //     throw new UnauthorizedException('Invalid email');
  //   }

  //   // Set the resetting password flag to true
  //   await this.prismaService.users.update({
  //     where: {
  //       id: user.id,
  //     },
  //     data: {
  //       reset_password: true,
  //     },
  //   });

  //   // Generate token
  //   const verificationToken = await this.getJwtVerificationToken(
  //     user.id,
  //     user.email,
  //     user.role,
  //   );

  //   // Generate verification link
  //   const verificationLink = `${process.env.FRONTEND_URL}/reset-password?token=${verificationToken}`; // Replace with frontend url

  //   // Send verification email with token
  //   const templateData = {
  //     fullname: user.first_name + ' ' + user.last_name,
  //     link: verificationLink,
  //   };

  //   const userEmail = user.email;
  //   const data: SendMailTemplateDto = {
  //     toAddresses: [userEmail],
  //     ccAddresses: [userEmail],
  //     bccAddresses: [userEmail],
  //     template: 'change_password_request',
  //     templateData: JSON.stringify(templateData),
  //   };

  //   try {
  //     await this.mailService.sendEmailTemplate(data);

  //   return {};
  // } catch (err) {
  //   throw new InternalServerErrorException('Forgot password email failed to send');
  // }
  // }

  // async resetPassword(userId: number, newPassword: string) {
  //   // Find user
  //   const user = await this.prismaService.users.findUnique({
  //     where: {
  //       id: userId,
  //     },
  //   });

  //   if (!user) {
  //     throw new UnauthorizedException('User not found');
  //   }

  //   if (user.reset_password == false) {
  //     throw new UnauthorizedException(
  //       'User has not requested for password reset',
  //     );
  //   }

  //   // Hash password
  //   const hash = await argon.hash(newPassword);

  //   // Update user password
  //   await this.prismaService.users.update({
  //     where: {
  //       id: userId,
  //     },
  //     data: {
  //       password: hash,
  //       reset_password: false,
  //     },
  //   });

  //   return {};
  // }

  // Utils
  async getJwtAccessToken(
    sub: number,
    email: string,
    role: string,
  ): Promise<string> {
    const payload: ITokenPayload = { sub, email, role };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_AT_SECRET,
      expiresIn: process.env.JWT_AT_EXPIRES,
    });
    return accessToken;
  }

  async getJwtRefreshToken(
    sub: number,
    email: string,
    role: string,
  ): Promise<string> {
    const payload: ITokenPayload = { sub, email, role };
    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_RT_SECRET,
      expiresIn: process.env.JWT_RT_EXPIRES,
    });
    return refreshToken;
  }

  async getJwtVerificationToken(
    sub: number,
    email: string,
    role: string,
  ): Promise<string> {
    const payload: ITokenPayload = { sub, email, role };
    const verificationToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_VT_SECRET,
      expiresIn: process.env.JWT_VT_EXPIRES,
    });
    return verificationToken;
  }

  private async generateTokens(payload: ITokenPayload) {
    const accessToken = await this.getJwtAccessToken(
      payload.sub,
      payload.email,
      payload.role,
    );

    const refreshToken = await this.getJwtRefreshToken(
      payload.sub,
      payload.email,
      payload.role,
    );

    const hash = await argon.hash(refreshToken);

    await this.prismaService.users.update({
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
