import { IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class BasicLoginRequestDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsOptional()
  fcmToken: string = undefined;
}
