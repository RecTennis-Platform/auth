import { IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class LoginHandleDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsNotEmpty()
  image: string;

  @IsString()
  @IsOptional()
  fcmToken: string = undefined;
}
