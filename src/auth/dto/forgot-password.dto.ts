import { IsEmail, IsNotEmpty } from 'class-validator';
import { Transform } from 'class-transformer';

export class ForgotPasswordDto {
  @Transform(({ value }) => value.toLowerCase())
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
