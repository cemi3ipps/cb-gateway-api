import { TypeCompiler } from "@sinclair/typebox/compiler"
import { t } from "elysia"

const structure = t.Object({
  NODE_ENV: t.String(),
  CB_SERVICE: t.String(),
  CB_CLIENT_ID: t.String(),
  CB_SECRET: t.String(),
  CB_CLIENT: t.String(),
  CB_ACCESS_TOKEN: t.String(),
  RSA_PUBLIC_KEY: t.String(),
  TO_BANK_BIC: t.String(),
  TO_BANK_ACC: t.String(),
})

const compiler = TypeCompiler.Compile(structure)

const toBool = (value: string | boolean) =>
  typeof value === "boolean" ? value : value === "true"

const parsedEnv = {
  ...process.env,
  //   CRON_UPAY_ENABLED: toBool(process.env.CRON_UPAY_ENABLED!),
}

if (!compiler.Check(parsedEnv)) throw new Error("Invalid environment variables")

export const env = compiler.Decode(parsedEnv)
