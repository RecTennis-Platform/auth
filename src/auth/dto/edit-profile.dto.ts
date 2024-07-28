import { Gender } from '@prisma/client';
import { IsEnum, IsOptional, IsString } from 'class-validator';

export class EditProfileDto {
  @IsString()
  @IsOptional()
  name?: string;

  @IsString()
  @IsOptional()
  phoneNumber?: string;

  @IsString()
  @IsOptional()
  dob?: string;

  @IsEnum(Gender)
  @IsOptional()
  gender?: Gender;

  @IsString()
  @IsOptional()
  image?: string;
}
