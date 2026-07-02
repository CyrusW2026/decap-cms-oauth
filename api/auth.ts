import { IncomingMessage, ServerResponse } from "http";
import { AuthorizationCode } from "simple-oauth2";
import { randomBytes } from "crypto";
import { config, Provider } from "../lib/config";
import { scopes } from "../lib/scopes";

export const randomString = () => randomBytes(4).toString("hex");

export default async (req: IncomingMessage, res: ServerResponse) => {
  try {
    const { host } = req.headers;
    const url = new URL(`https://${host}/${req.url}`);
    const urlParams = url.searchParams;
    
    // ✅ 加入預設值，避免 provider 為 null 時崩潰
    const provider = (urlParams.get("provider") as Provider) || "github";

    // ✅ 檢查 provider 是否有效
    if (!provider || !scopes[provider]) {
      throw new Error(`Unsupported or missing provider: ${provider}`);
    }

    const client = new AuthorizationCode(config(provider));

    const authorizationUri = client.authorizeURL({
      redirect_uri: `https://${host}/callback?provider=${provider}`,
      scope: scopes[provider],
      state: randomString(),
    });

    res.writeHead(301, { Location: authorizationUri });
    res.end();
  } catch (error) {
    // ✅ 錯誤處理，返回清晰的錯誤訊息
    console.error("[OAuth Auth Error]", error);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ 
      error: "Authorization failed", 
      message: error instanceof Error ? error.message : String(error)
    }));
  }
};
