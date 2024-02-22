import { IsNotEmpty, IsString } from 'class-validator';

export class GoogleLoginRequestDto {
  @IsString()
  @IsNotEmpty()
  token: string;
}
