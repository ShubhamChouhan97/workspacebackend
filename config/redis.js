const redis = require('ioredis');

const { 
    redisIp = "localhost", redisPort = 6379, redisPassword,
    sessionRedisIp = "localhost", sessionRedisPort = 6379, sessionRedisPassword,
 } = require('./configVars');

const redisConfig = {
    port: redisPort,
    host: redisIp,
    // password: redisPassword,
}

const sessionRedisConfig = {
    port: sessionRedisPort,
    host: sessionRedisIp,
    password: sessionRedisPassword,
}

/**
 * 
 * @param {{isSessionRedis: boolean}| {}} param0 
 * @returns 
 */
function connectRedis(config) {
    let redisClient = null;
    const isSessionRedis = config?.isSessionRedis;
     if (isSessionRedis) {
        redisClient = new redis(sessionRedisConfig)
    } else {
        redisClient = new redis(redisConfig);
    }

    redisClient.on('error', (err) => {
        console.log('Redis error: ' + err);
        process.exit(1);
    })

    redisClient.on('connect', () => {
        if (isSessionRedis) {
            console.log('Session Redis is Connected');
            return;
        }
        console.log('Redis is connected');
    })

    return redisClient;
}

module.exports = {
    connectRedis,
}
