import type { Prisma } from '@prisma/client';

export const selectAuthUser: Prisma.UserSelect = {
  id: true,
  name: true,
  email: true,
  role: true,
};
