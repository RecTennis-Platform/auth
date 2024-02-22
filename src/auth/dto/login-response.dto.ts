import { User } from '@prisma/client';

export class LoginResponseDto {
  accessToken: string;
  refreshToken: string;
  user: {
    email: User['email'];
    name: User['name'];
    image: User['image'];
  };
}
