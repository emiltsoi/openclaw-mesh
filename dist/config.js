export function resolveSecret(api) {
    // pluginConfig may not include secret (OpenClaw strips sensitive fields)
    const pluginCfg = api.pluginConfig || {};
    if (pluginCfg.secret)
        return pluginCfg.secret;
    // Fall back to full gateway config
    const fullCfg = api.config?.plugins?.entries?.["a2a-bridge"]?.config ?? {};
    if (fullCfg.secret)
        return fullCfg.secret;
    const envVarName = pluginCfg.secretEnvVar || "A2A_BRIDGE_SECRET";
    const envSecret = process.env[envVarName];
    if (envSecret)
        return envSecret;
    throw new Error("a2a-bridge: no secret configured.");
}
