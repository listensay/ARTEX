// Schema and SHA-256 format follow ScopeSentry d770b7a137ec2de15816fea4bd561f49cf486db2.
const fs = require('fs');
const crypto = require('crypto');
const secretDir = '/run/scopesentry-secrets/';
const mongo = new Mongo('mongodb://scopesentry-mongodb:27017');
if (!mongo.getDB('admin').auth({
  user: process.env.MONGODB_USER,
  pwd: fs.readFileSync(secretDir + 'mongo-password', 'utf8').trim(),
})) throw new Error('MongoDB authentication failed');
const database = mongo.getDB(process.env.MONGODB_DATABASE || 'ScopeSentry');
const marker = 'artex-managed-api-key-v1';
if (!database.artex_bootstrap.findOne({_id: marker})) {
  const key = fs.readFileSync(secretDir + 'api-key', 'utf8').trim();
  if (!/^ssk_[a-f0-9]{40}$/.test(key)) throw new Error('Invalid API key file');
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  database.api_key.updateOne({keyHash}, {$setOnInsert: {
    name: 'ARTEX Docker', keyHash, keyPrefix: key.slice(0, 12) + '...',
    enabled: true, createdBy: 'ARTEX Docker bootstrap', createdAt: new Date(),
  }}, {upsert: true});
  database.artex_bootstrap.updateOne({_id: marker}, {$setOnInsert: {
    createdAt: new Date(), keyHash,
  }}, {upsert: true});
  print('[scopesentry] ARTEX API key registered');
} else {
  print('[scopesentry] existing API key configuration preserved');
}
