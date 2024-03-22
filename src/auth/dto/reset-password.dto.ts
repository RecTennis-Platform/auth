import { IsString, IsNotEmpty } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  @IsNotEmpty()
  verifyToken: string;

  @IsString()
  @IsNotEmpty()
  newPassword: string;
}
