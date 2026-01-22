import { Injectable, ExecutionContext, Logger } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerException } from '@nestjs/throttler';
import { Reflector } from '@nestjs/core';
import { SKIP_THROTTLE_KEY } from '../decorators/skip-throttle.decorator';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  private readonly logger = new Logger(CustomThrottlerGuard.name);

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const reflector = new Reflector();
    const skipThrottle = reflector.getAllAndOverride<boolean>(SKIP_THROTTLE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skipThrottle) {
      return true;
    }

    try {
      return await super.canActivate(context);
    } catch (error) {
      if (error instanceof ThrottlerException) {
        const request = context.switchToHttp().getRequest();
        this.logger.warn(
          `Rate limit exceeded for IP: ${request.ip}, Path: ${request.path}`,
        );
      }
      throw error;
    }
  }

  protected async getTracker(req: Record<string, unknown>): Promise<string> {
    const forwarded = (req.headers as { 'x-forwarded-for'?: string })?.['x-forwarded-for'];
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    return (req.ip as string) || (req.socket as { remoteAddress?: string })?.remoteAddress || 'unknown';
  }
}
