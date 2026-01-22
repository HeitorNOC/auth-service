import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { PrismaService } from '@/prisma/prisma.service';
import { RedisService } from '@/common/redis/redis.service';
import { Public, SkipThrottle } from '@/common/decorators';

@ApiTags('Health')
@Controller('health')
@Public()
@SkipThrottle()
export class HealthController {
  constructor(
    private prisma: PrismaService,
    private redisService: RedisService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Basic health check' })
  @ApiResponse({ status: 200 })
  health() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness check with dependencies' })
  @ApiResponse({ status: 200 })
  async readiness() {
    const checks = {
      database: 'unknown',
      redis: 'unknown',
    };

    try {
      const dbHealthy = await this.prisma.healthCheck();
      checks.database = dbHealthy ? 'healthy' : 'unhealthy';
    } catch {
      checks.database = 'unhealthy';
    }

    try {
      await this.redisService.set('health-check', 'ok', 10);
      const value = await this.redisService.get('health-check');
      checks.redis = value === 'ok' ? 'healthy' : 'unhealthy';
    } catch {
      checks.redis = 'unhealthy';
    }

    const allHealthy = Object.values(checks).every((s) => s === 'healthy');

    return {
      status: allHealthy ? 'ready' : 'degraded',
      timestamp: new Date().toISOString(),
      dependencies: checks,
    };
  }

  @Get('live')
  @ApiOperation({ summary: 'Liveness probe' })
  @ApiResponse({ status: 200 })
  liveness() {
    return {
      status: 'alive',
      timestamp: new Date().toISOString(),
    };
  }
}
