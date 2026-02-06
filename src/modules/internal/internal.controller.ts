import { Controller, Post, Body, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiSecurity, ApiBody } from '@nestjs/swagger';
import { InternalService } from './internal.service';
import { InternalApiGuard } from '@/common/guards';

@ApiTags('Internal')
@Controller('internal')
// Removido InternalApiGuard e ApiSecurity, não exige mais API key
export class InternalController {
  constructor(private readonly internalService: InternalService) {}

  @Post('resolve-context')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Resolve user context from access token' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['accessToken'],
      properties: {
        accessToken: { type: 'string' },
      },
    },
  })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 401 })
    async resolveContext(@Body('accessToken') accessToken: string) {
      const result = await this.internalService.resolveContext(accessToken);
      console.log('[InternalController] /internal/resolve-context', result ? 200 : 401);
      return result;
  }

  @Post('verify-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify access token validity' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['accessToken'],
      properties: {
        accessToken: { type: 'string' },
      },
    },
  })
  @ApiResponse({ status: 200 })
    async verifyToken(@Body('accessToken') accessToken: string) {
      console.log('[InternalController] /internal/verify-token called');
      const result = await this.internalService.verifyToken(accessToken);
      console.log('[InternalController] /internal/verify-token', result.valid ? 200 : 401);
      return result;
  }

  @Post('check-permissions')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Check if user has required permissions' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['userId', 'accountId', 'permissions'],
      properties: {
        userId: { type: 'string' },
        accountId: { type: 'string' },
        permissions: { type: 'array', items: { type: 'string' } },
        mode: { type: 'string', enum: ['ANY', 'ALL'], default: 'ANY' },
      },
    },
  })
  @ApiResponse({ status: 200 })
    async checkPermissions(
      @Body('userId') userId: string,
      @Body('accountId') accountId: string,
      @Body('permissions') permissions: string[],
      @Body('mode') mode: 'ANY' | 'ALL' = 'ANY',
    ) {
      const result = await this.internalService.checkPermissions(userId, accountId, permissions, mode);
      console.log('[InternalController] /internal/check-permissions', result ? 200 : 401);
      console.log('[InternalController] /internal/check-permissions result:', result);
      return result;
  }

  @Post('check-roles')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Check if user has required roles' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['userId', 'accountId', 'roles'],
      properties: {
        userId: { type: 'string' },
        accountId: { type: 'string' },
        roles: { type: 'array', items: { type: 'string' } },
      },
    },
  })
  @ApiResponse({ status: 200 })
  async checkRoles(
    @Body('userId') userId: string,
    @Body('accountId') accountId: string,
    @Body('roles') roles: string[],
  ) {
    const hasRole = await this.internalService.checkRoles(userId, accountId, roles);
    return { hasRole };
  }

  @Post('user-info')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get user information' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['userId', 'accountId'],
      properties: {
        userId: { type: 'string' },
        accountId: { type: 'string' },
      },
    },
  })
  @ApiResponse({ status: 200 })
  async getUserInfo(@Body('userId') userId: string, @Body('accountId') accountId: string) {
    return this.internalService.getUserInfo(userId, accountId);
  }
}
