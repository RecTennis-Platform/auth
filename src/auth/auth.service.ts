import {
  BadRequestException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon from 'argon2';

import { JwtService } from '@nestjs/jwt';
import { Gender } from '@prisma/client';
import { ResponseDto } from 'src/helper';
import { PrismaService } from 'src/prisma/prisma.service';
import { SendMailTemplateDto } from 'src/services/mail/mail.dto';
import { MailService } from 'src/services/mail/mail.service';
import {
  ChangePasswordDto,
  LoginHandleDto,
  LoginResponseDto,
  SignUpRequestDto,
} from './dto';
import { BasicLoginRequestDto } from './dto/basic-login-request.dto';
import { ITokenPayload } from './interfaces';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private readonly mailService: MailService,
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
    });

    await this.prismaService.users.update({
      where: {
        id: user.id,
      },
      data: {
        fcmToken: loginDto.fcmToken,
      },
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        image: user.image,
        role: user.role,
        gender: user.gender,
        phoneNumber: user.phoneNumber,
        dob: user.dob,
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
            gender: Gender.male,
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

    await this.prismaService.users.update({
      where: {
        id: user.id,
      },
      data: {
        fcmToken: loginDto.fcmToken,
      },
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        image: user.image,
        role: user.role,
        gender: user.gender,
        phoneNumber: user.phoneNumber,
        dob: user.dob,
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
        gender: signUpDto.gender,
        phoneNumber: signUpDto.phoneNumber,
        dob: signUpDto.dob,
        fcmToken: signUpDto.fcmToken,
      },
    });

    // Generate tokens
    const tokens = await this.generateTokens({
      sub: newUser.id,
      email: newUser.email,
    });

    return {
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        image: newUser.image,
        role: newUser.role,
        gender: newUser.gender,
        phoneNumber: newUser.phoneNumber,
        dob: newUser.dob,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async logOut(userId: string): Promise<ResponseDto> {
    const user = await this.prismaService.users.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    try {
      if (user.refreshToken) {
        // Update user's refresh token to null
        await this.prismaService.users.update({
          where: {
            id: userId,
          },
          data: {
            refreshToken: null,
          },
        });
      }

      return new ResponseDto(HttpStatus.OK, 'success', null);
    } catch (err) {
      console.log('Error:', err);
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async refresh(
    refreshToken: string,
    payload: ITokenPayload,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
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
    userId: string,
    dto: ChangePasswordDto,
  ): Promise<ResponseDto> {
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

      return new ResponseDto<string>(HttpStatus.OK, 'success', null);
    } catch (err) {
      console.log('Error:', err);
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async forgotPassword(email: string) {
    // Find user
    const user = await this.prismaService.users.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Set the resetting password flag to true
    await this.prismaService.users.update({
      where: {
        id: user.id,
      },
      data: {
        resetPassword: true,
      },
    });

    // Generate token
    const verificationToken = await this.getJwtVerificationToken(
      user.id,
      user.email,
    );

    // Generate verification link
    const verificationLink = `${process.env.FRONTEND_URL}/reset-password?token=${verificationToken}`; // Replace with frontend url

    // Send verification email with token
    const templateData = {
      fullname: user.name,
      link: verificationLink,
    };

    const userEmail = user.email;
    const data: SendMailTemplateDto = {
      toAddresses: [userEmail],
      ccAddresses: [userEmail],
      bccAddresses: [userEmail],
      template: 'change_password_request',
      templateData: JSON.stringify(templateData),
    };

    try {
      await this.mailService.sendEmailTemplate(data);

      return {};
    } catch (err) {
      throw new InternalServerErrorException(
        'Forgot password email failed to send',
      );
    }
  }

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
  async getJwtAccessToken(sub: string, email: string): Promise<string> {
    const payload: ITokenPayload = { sub, email };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_AT_SECRET,
      expiresIn: process.env.JWT_AT_EXPIRES,
    });
    return accessToken;
  }

  async getJwtRefreshToken(sub: string, email: string): Promise<string> {
    const payload: ITokenPayload = { sub, email };
    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_RT_SECRET,
      expiresIn: process.env.JWT_RT_EXPIRES,
    });
    return refreshToken;
  }

  async getJwtVerificationToken(sub: string, email: string): Promise<string> {
    const payload: ITokenPayload = { sub, email };
    const verificationToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_VT_SECRET,
      expiresIn: process.env.JWT_VT_EXPIRES,
    });
    return verificationToken;
  }

  private async generateTokens(payload: ITokenPayload): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    const accessToken = await this.getJwtAccessToken(
      payload.sub,
      payload.email,
    );

    const refreshToken = await this.getJwtRefreshToken(
      payload.sub,
      payload.email,
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
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }
}
