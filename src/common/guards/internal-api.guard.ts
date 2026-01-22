import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class InternalApiGuard implements CanActivate {
  private readonly logger = new Logger(InternalApiGuard.name);
  private readonly internalApiKey: string;

  constructor(private configService: ConfigService) {
    this.internalApiKey = this.configService.get<string>('INTERNAL_API_KEY', '');
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const apiKey = request.headers['x-internal-api-key'] as string;

    if (!apiKey) {
      this.logger.warn('Internal API key missing');
      throw new UnauthorizedException('Internal API key required');
    }

    if (!this.internalApiKey) {
      this.logger.error('Internal API key not configured');
      throw new UnauthorizedException('Internal API not configured');
    }

    if (apiKey !== this.internalApiKey) {
      this.logger.warn('Invalid internal API key');
      throw new UnauthorizedException('Invalid internal API key');
    }

    return true;
  }
}
