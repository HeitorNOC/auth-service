import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

const DEFAULT_PERMISSIONS = [
  { code: 'users:view', name: 'View Users', resource: 'users', action: 'view' },
  { code: 'users:create', name: 'Create Users', resource: 'users', action: 'create' },
  { code: 'users:update', name: 'Update Users', resource: 'users', action: 'update' },
  { code: 'users:delete', name: 'Delete Users', resource: 'users', action: 'delete' },
  { code: 'users:manage-roles', name: 'Manage User Roles', resource: 'users', action: 'manage-roles' },
  { code: 'users:deactivate', name: 'Deactivate Users', resource: 'users', action: 'deactivate' },
  { code: 'users:activate', name: 'Activate Users', resource: 'users', action: 'activate' },
  { code: 'roles:view', name: 'View Roles', resource: 'roles', action: 'view' },
  { code: 'roles:create', name: 'Create Roles', resource: 'roles', action: 'create' },
  { code: 'roles:update', name: 'Update Roles', resource: 'roles', action: 'update' },
  { code: 'roles:delete', name: 'Delete Roles', resource: 'roles', action: 'delete' },
  { code: 'roles:manage-permissions', name: 'Manage Role Permissions', resource: 'roles', action: 'manage-permissions' },
  { code: 'account:view', name: 'View Account', resource: 'account', action: 'view' },
  { code: 'account:update', name: 'Update Account', resource: 'account', action: 'update' },
  { code: 'account:manage-settings', name: 'Manage Account Settings', resource: 'account', action: 'manage-settings' },
  { code: 'invitations:view', name: 'View Invitations', resource: 'invitations', action: 'view' },
  { code: 'invitations:create', name: 'Create Invitations', resource: 'invitations', action: 'create' },
  { code: 'invitations:cancel', name: 'Cancel Invitations', resource: 'invitations', action: 'cancel' },
  { code: 'sessions:view', name: 'View Sessions', resource: 'sessions', action: 'view' },
  { code: 'sessions:revoke', name: 'Revoke Sessions', resource: 'sessions', action: 'revoke' },
  { code: 'audit:view', name: 'View Audit Logs', resource: 'audit', action: 'view' },
  { code: 'jobs:view', name: 'View Jobs', resource: 'jobs', action: 'view' },
  { code: 'jobs:create', name: 'Create Jobs', resource: 'jobs', action: 'create' },
  { code: 'jobs:update', name: 'Update Jobs', resource: 'jobs', action: 'update' },
  { code: 'jobs:delete', name: 'Delete Jobs', resource: 'jobs', action: 'delete' },
  { code: 'payments:view', name: 'View Payments', resource: 'payments', action: 'view' },
  { code: 'payments:manage', name: 'Manage Payments', resource: 'payments', action: 'manage' },
  { code: 'clients:view', name: 'View Clients', resource: 'clients', action: 'view' },
  { code: 'clients:create', name: 'Create Clients', resource: 'clients', action: 'create' },
  { code: 'clients:update', name: 'Update Clients', resource: 'clients', action: 'update' },
  { code: 'clients:delete', name: 'Delete Clients', resource: 'clients', action: 'delete' },
];

const ROLE_PERMISSIONS = {
  OWNER: DEFAULT_PERMISSIONS.map((p) => p.code),
  ADMIN: [
    'users:view', 'users:create', 'users:update', 'users:manage-roles',
    'users:deactivate', 'users:activate',
    'roles:view', 'roles:create', 'roles:update',
    'account:view', 'account:update',
    'invitations:view', 'invitations:create', 'invitations:cancel',
    'sessions:view', 'sessions:revoke',
    'audit:view',
    'jobs:view', 'jobs:create', 'jobs:update', 'jobs:delete',
    'clients:view', 'clients:create', 'clients:update',
    'payments:view',
  ],
  WORKER: [
    'users:view',
    'roles:view',
    'jobs:view', 'jobs:create', 'jobs:update',
    'clients:view',
  ],
  CLIENT: [
    'jobs:view',
    'payments:view',
  ],
};

async function main() {
  console.log('Starting database seed...');

  console.log('Creating permissions...');
  for (const perm of DEFAULT_PERMISSIONS) {
    await prisma.permission.upsert({
      where: { code: perm.code },
      update: {},
      create: {
        code: perm.code,
        name: perm.name,
        resource: perm.resource,
        action: perm.action,
      },
    });
  }
  console.log(`Created ${DEFAULT_PERMISSIONS.length} permissions`);

  console.log('Creating demo account...');
  const account = await prisma.account.upsert({
    where: { slug: 'demo-account' },
    update: {},
    create: {
      name: 'Demo Account',
      slug: 'demo-account',
      status: 'ACTIVE',
    },
  });
  console.log(`Account created: ${account.id}`);

  console.log('Creating roles...');
  const roles: Record<string, { id: string }> = {};

  for (const roleName of ['OWNER', 'ADMIN', 'WORKER', 'CLIENT']) {
    const role = await prisma.role.upsert({
      where: { accountId_name: { accountId: account.id, name: roleName } },
      update: {},
      create: {
        accountId: account.id,
        name: roleName,
        isSystem: true,
      },
    });
    roles[roleName] = role;

    await prisma.rolePermission.deleteMany({
      where: { roleId: role.id },
    });

    const permissionCodes = ROLE_PERMISSIONS[roleName as keyof typeof ROLE_PERMISSIONS];
    const permissions = await prisma.permission.findMany({
      where: { code: { in: permissionCodes } },
    });

    for (const perm of permissions) {
      await prisma.rolePermission.create({
        data: {
          roleId: role.id,
          permissionId: perm.id,
        },
      });
    }
    console.log(`Role ${roleName} created with ${permissions.length} permissions`);
  }

  console.log('Creating demo users...');
  const passwordHash = await bcrypt.hash('Demo@123', 12);

  const demoUsers = [
    { email: 'owner@demo.com', firstName: 'Demo', lastName: 'Owner', role: 'OWNER' },
    { email: 'admin@demo.com', firstName: 'Demo', lastName: 'Admin', role: 'ADMIN' },
    { email: 'worker@demo.com', firstName: 'Demo', lastName: 'Worker', role: 'WORKER' },
  ];

  for (const userData of demoUsers) {
    const existingUser = await prisma.user.findUnique({
      where: { accountId_email: { accountId: account.id, email: userData.email } },
    });

    if (existingUser) {
      console.log(`User ${userData.email} already exists, skipping...`);
      continue;
    }

    const user = await prisma.user.create({
      data: {
        accountId: account.id,
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName,
        status: 'ACTIVE',
        emailVerified: true,
        emailVerifiedAt: new Date(),
      },
    });

    await prisma.credential.create({
      data: {
        userId: user.id,
        passwordHash,
        passwordChangedAt: new Date(),
      },
    });

    await prisma.userRole.create({
      data: {
        userId: user.id,
        roleId: roles[userData.role].id,
      },
    });

    console.log(`User ${userData.email} created with role ${userData.role}`);
  }

  console.log('Seed completed successfully');
}

main()
  .catch((e) => {
    console.error('Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
