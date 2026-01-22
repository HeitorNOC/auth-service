import { Controller, Post, Body, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiSecurity, ApiBody } from '@nestjs/swagger';
import { InternalService } from './internal.service';
import { InternalApiGuard } from '@/common/guards';
import { SkipThrottle } from '@/common/decorators';

@ApiTags('Internal')
@Controller('internal')
@UseGuards(InternalApiGuard)
@ApiSecurity('internal-api-key')
@SkipThrottle()
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
    return this.internalService.resolveContext(accessToken);
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
    return this.internalService.verifyToken(accessToken);
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
    const hasPermission = await this.internalService.checkPermissions(
      userId,
      accountId,
      permissions,
      mode,
    );
    return { hasPermission };
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
