import { users } from '@prisma/client';

export class LoginResponseDto {
  accessToken: string;
  refreshToken: string;
  user: {
    id: users['id'];
    email: users['email'];
    name: users['name'];
    image: users['image'];
    role: users['role'];
    gender: users['gender'];
    dob: users['dob'];
    phoneNumber: users['phoneNumber'];
  };
}
