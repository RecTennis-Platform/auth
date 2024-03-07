import { users } from '@prisma/client';

export class LoginResponseDto {
  accessToken: string;
  refreshToken: string;
  user: {
    email: users['email'];
    name: users['name'];
    image: users['image'];
  };
}
