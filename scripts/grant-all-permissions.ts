/*
  Script: Grant all permissions to a user by creating/assigning a role
  Usage:
    npm run grant:all-permissions -- <USER_ID>

  Requires:
    - DATABASE_URL env var set
    - Optional: REDIS_URL env var to clear permission/role cache
*/

import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

async function main() {
  const userId = process.argv[2];
  if (!userId) {
    console.error('Usage: npm run grant:all-permissions -- <USER_ID>');
    process.exit(1);
  }

  const prisma = new PrismaClient({ datasources: { db: { url: process.env.DATABASE_URL } } });

  let redis: Redis | null = null;
  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    try {
      redis = new Redis(redisUrl, {
        retryStrategy: (times) => Math.min(times * 50, 2000),
        maxRetriesPerRequest: 3,
      });
    } catch (e) {
      console.warn('Redis init failed; cache invalidation will be skipped.');
    }
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, accountId: true, email: true },
    });

    if (!user) {
      throw new Error(`User not found: ${userId}`);
    }

    const accountId = user.accountId;

    // Ensure the role exists or create it
    const roleName = 'SUPERUSER';
    let role = await prisma.role.findUnique({
      where: { accountId_name: { accountId, name: roleName } },
    });

    if (!role) {
      role = await prisma.role.create({
        data: {
          accountId,
          name: roleName,
          description: 'Role with all permissions for this account',
          isSystem: true,
        },
      });
    }

    // Fetch all permissions (global)
    const permissions = await prisma.permission.findMany({ select: { id: true } });
    const permissionIds = permissions.map((p) => p.id);

    // Replace role permissions with all permissions
    await prisma.$transaction([
      prisma.rolePermission.deleteMany({ where: { roleId: role.id } }),
      prisma.rolePermission.createMany({
        data: permissionIds.map((permissionId) => ({ roleId: role!.id, permissionId })),
        skipDuplicates: true,
      }),
    ]);

    // Ensure user has the role
    const existingUserRole = await prisma.userRole.findUnique({
      where: { userId_roleId: { userId: user.id, roleId: role.id } },
    });

    if (!existingUserRole) {
      await prisma.userRole.create({
        data: { userId: user.id, roleId: role.id },
      });
    }

    // Invalidate Redis caches for user permissions/roles
    if (redis) {
      const permKey = `auth:permissions:${accountId}:${userId}`;
      const roleKey = `auth:roles:${accountId}:${userId}`;
      await redis.del(permKey);
      await redis.del(roleKey);
      await redis.quit();
    }

    console.log('Success: granted all permissions to user');
    console.log(JSON.stringify({ userId: userId, accountId, roleId: role.id }, null, 2));
  } catch (error) {
    console.error('Error granting permissions:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();
