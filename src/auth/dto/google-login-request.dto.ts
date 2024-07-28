import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class GoogleLoginRequestDto {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsOptional()
  fcmToken: string = undefined;
}
