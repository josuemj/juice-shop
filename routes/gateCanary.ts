import * as models from '../models/index'

// Canario para probar el security gate (Hito 2). NO usar: se elimina en el commit siguiente.
export async function gateCanary (input: string) {
  return await models.sequelize.query(`SELECT * FROM Users WHERE email = '${input}'`)
}
