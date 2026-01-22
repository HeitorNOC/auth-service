import { SetMetadata } from '@nestjs/common';

export const PERMISSIONS_KEY = 'permissions';

export interface PermissionRequirement {
  permissions: string[];
  mode: 'ANY' | 'ALL';
}

export const RequirePermissions = (
  permissions: string | string[],
  mode: 'ANY' | 'ALL' = 'ANY',
) => {
  const permArray = Array.isArray(permissions) ? permissions : [permissions];
  return SetMetadata(PERMISSIONS_KEY, { permissions: permArray, mode });
};

export const RequireAllPermissions = (...permissions: string[]) =>
  RequirePermissions(permissions, 'ALL');

export const RequireAnyPermission = (...permissions: string[]) =>
  RequirePermissions(permissions, 'ANY');
