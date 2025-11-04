import { Router } from 'express';
import { supabase } from '@shared/supabase';

const router = Router();

// Health check endpoint
router.get('/', async (req, res) => {
  try {
    // Check database connectivity
    const { data, error } = await supabase
      .from('profiles')
      .select('id')
      .limit(1);

    const dbStatus = error ? 'unhealthy' : 'healthy';

    // Check external API connectivity (OpenRouter)
    let aiStatus = 'unknown';
    try {
      const response = await fetch('https://openrouter.ai/api/v1/models', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY || 'test'}`,
        },
        signal: AbortSignal.timeout(5000) // 5 second timeout
      });
      aiStatus = response.ok ? 'healthy' : 'unhealthy';
    } catch (aiError) {
      aiStatus = 'unhealthy';
    }

    const health = {
      status: dbStatus === 'healthy' && aiStatus === 'healthy' ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      services: {
        database: dbStatus,
        ai_service: aiStatus,
        server: 'healthy'
      },
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0'
    };

    const statusCode = health.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
      services: {
        database: 'unknown',
        ai_service: 'unknown',
        server: 'unhealthy'
      }
    });
  }
});

// Detailed health check
router.get('/detailed', async (req, res) => {
  try {
    const startTime = Date.now();

    // Database health
    const dbStart = Date.now();
    const { data: dbData, error: dbError } = await supabase
      .from('medical_records')
      .select('count', { count: 'exact', head: true });
    const dbResponseTime = Date.now() - dbStart;

    // Memory usage
    const memUsage = process.memoryUsage();

    // System info
    const systemInfo = {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      uptime: process.uptime(),
      pid: process.pid
    };

    const health = {
      status: dbError ? 'degraded' : 'healthy',
      timestamp: new Date().toISOString(),
      responseTime: Date.now() - startTime,
      services: {
        database: {
          status: dbError ? 'unhealthy' : 'healthy',
          responseTime: dbResponseTime,
          recordCount: dbData ? dbData.length : 0,
          error: dbError?.message
        }
      },
      system: {
        memory: {
          rss: Math.round(memUsage.rss / 1024 / 1024) + 'MB',
          heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB',
          heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
          external: Math.round(memUsage.external / 1024 / 1024) + 'MB'
        },
        ...systemInfo
      },
      environment: process.env.NODE_ENV || 'development'
    };

    res.json(health);
  } catch (error) {
    console.error('Detailed health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Detailed health check failed'
    });
  }
});

export { router as healthRoutes };