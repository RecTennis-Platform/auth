import { IsEmail, IsNotEmpty, IsString, IsNumber } from 'class-validator';

export class TokenPayloadDto {
  @IsString()
  @IsNotEmpty()
  sub: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsNumber()
  iat?: number;

  @IsNumber()
  exp?: number;

  @IsNumber()
  groupId?: number;
}
