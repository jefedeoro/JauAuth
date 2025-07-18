//! Simple MCP Router - A basic implementation without full MCP SDK integration

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::sync::Arc;
use tracing::{info, error};

use crate::sandbox::{SandboxConfig, SandboxStrategy};
use crate::backend_manager::BackendManager;

/// Allowed commands for security - prevents arbitrary command execution
pub const ALLOWED_COMMANDS: &[&str] = &[
    "npx", "node", "npm", "yarn", "pnpm", "bun", "deno",
    "python", "python3", "pip", "pipx",
    "cargo", "rustc",
    "go", "docker", "podman",
    "java", "gradle", "mvn",
    "dotnet", "ruby", "gem",
    "/usr/bin/npx", "/usr/local/bin/npx", // Common absolute paths
];

/// Check if a command is in the allowed list
pub fn is_command_allowed(command: &str) -> bool {
    ALLOWED_COMMANDS.contains(&command)
}

/// Validate that a string doesn't contain shell metacharacters
pub fn validate_shell_safety(arg: &str) -> bool {
    // Reject if contains shell metacharacters
    let dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '\n', '\r', '<', '>'];
    !arg.chars().any(|c| dangerous_chars.contains(&c))
}

/// Configuration for a backend MCP server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendServer {
    /// Unique identifier for this server
    pub id: String,
    /// Display name for the server
    pub name: String,
    /// Server type (local or remote)
    #[serde(default = "default_server_type")]
    pub r#type: ServerType,
    /// Command to launch the server (for local servers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Arguments for the command (for local servers)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// URL for remote servers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Transport type for remote servers
    #[serde(default = "default_transport")]
    pub transport: TransportType,
    /// Authentication configuration for remote servers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RemoteAuthConfig>,
    /// Environment variables
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Whether authentication is required for this server
    pub requires_auth: bool,
    /// Allowed users/roles (if requires_auth is true)
    pub allowed_users: Vec<String>,
    /// Sandbox configuration (optional, defaults to platform default)
    #[serde(default)]
    pub sandbox: SandboxConfig,
    /// Timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Retry configuration for remote servers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,
    /// TLS configuration for remote servers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

/// Server type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServerType {
    Local,
    Remote,
}

/// Transport type for remote servers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Sse,
    #[serde(rename = "websocket")]
    WebSocket,
}

/// Remote authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RemoteAuthConfig {
    None,
    Bearer { token: String },
    Basic { username: String, password: String },
    OAuth {
        provider: String,
        client_id: String,
        client_secret: String,
        #[serde(default)]
        scopes: Vec<String>,
    },
    Custom {
        headers: HashMap<String, String>,
    },
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RetryConfig {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default = "default_true")]
    pub verify_cert: bool,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

// Default functions
fn default_server_type() -> ServerType { ServerType::Local }
fn default_transport() -> TransportType { TransportType::Sse }
fn default_timeout_ms() -> u64 { 30000 }
fn default_max_attempts() -> u32 { 3 }
fn default_initial_backoff_ms() -> u64 { 1000 }
fn default_max_backoff_ms() -> u64 { 30000 }
fn default_true() -> bool { true }

/// Configuration for the router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// List of backend servers to route to
    pub servers: Vec<BackendServer>,
    /// Default timeout for backend operations (ms)
    pub timeout_ms: u64,
    /// Whether to cache tool listings
    pub cache_tools: bool,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            servers: vec![],
            timeout_ms: 30000,
            cache_tools: true,
        }
    }
}

/// Simple router that manages and routes to backend MCP servers
pub struct SimpleRouter {
    config: RouterConfig,
    backend_manager: Arc<BackendManager>,
}

/// Validate that a command is in the allowlist
fn validate_command(cmd: &str) -> Result<()> {
    // Check if command is in allowlist (handle both simple commands and paths)
    let is_allowed = ALLOWED_COMMANDS.iter().any(|&allowed| {
        cmd == allowed || cmd.ends_with(format!("/{}", allowed).as_str())
    });
    
    if !is_allowed {
        return Err(anyhow!(
            "Command '{}' is not in the allowlist. Allowed commands: {:?}", 
            cmd, ALLOWED_COMMANDS
        ));
    }
    
    // Additional validation: no shell metacharacters (except $ for env vars)
    if cmd.contains(&['|', ';', '&', '`', '>', '<', '(', ')'][..]) {
        return Err(anyhow!("Command contains potentially dangerous characters"));
    }
    
    // Check for dangerous command substitution patterns
    if cmd.contains("$(") || cmd.contains("$`") || cmd.contains("${(") || cmd.contains("${`") {
        return Err(anyhow!("Command contains dangerous command substitution"));
    }
    
    Ok(())
}

/// Validate server configuration for security
pub async fn validate_server_config(server: &BackendServer) -> Result<()> {
    // Validate server ID (alphanumeric + dash/underscore only)
    if !server.id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(anyhow!("Server ID must be alphanumeric with dashes/underscores only"));
    }
    
    match server.r#type {
        ServerType::Local => {
            // Validate command for local servers
            let command = server.command.as_ref()
                .ok_or_else(|| anyhow!("Local server must have a command"))?;
            validate_command(command)?;
            
            // Validate arguments don't contain shell injection attempts
            for arg in &server.args {
                // Allow environment variable references like $USER, $HOME, ${VAR}
                let has_env_var = arg.contains('$');
                
                // Check for dangerous characters (excluding $ for env vars)
                if arg.contains(&['|', ';', '&', '`'][..]) {
                    return Err(anyhow!("Argument contains potentially dangerous characters: {}", arg));
                }
                
                // If it has $, validate it's a proper env var reference
                if has_env_var {
                    // Check for common dangerous patterns with $
                    if arg.contains("$(") || arg.contains("$`") || arg.contains("${(") || arg.contains("${`") {
                        return Err(anyhow!("Argument contains dangerous command substitution: {}", arg));
                    }
                    
                    // Validate it looks like a proper env var reference
                    // Allow: $VAR, ${VAR}, $VAR_NAME, text$VAR, etc.
                    // This is a basic check - the actual env var expansion happens at runtime
                    if !arg.chars().any(|c| c.is_alphanumeric() || c == '_' || c == '=' || c == '-' || c == '/' || c == '.' || c == ':') {
                        return Err(anyhow!("Argument appears to be invalid: {}", arg));
                    }
                }
            }
            
            // Validate sandbox strategy is available
            crate::sandbox::validate_sandbox_strategy(&server.sandbox.strategy).await
                .map_err(|e| anyhow!("Sandbox validation failed: {}", e))?;
        }
        ServerType::Remote => {
            // Validate URL for remote servers
            let url = server.url.as_ref()
                .ok_or_else(|| anyhow!("Remote server must have a URL"))?;
            
            // Basic URL validation
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(anyhow!("Remote server URL must start with http:// or https://"));
            }
            
            // Validate auth config if present
            if let Some(auth) = &server.auth {
                match auth {
                    RemoteAuthConfig::Bearer { token } => {
                        if token.is_empty() {
                            return Err(anyhow!("Bearer token cannot be empty"));
                        }
                    }
                    RemoteAuthConfig::Basic { username, password } => {
                        if username.is_empty() || password.is_empty() {
                            return Err(anyhow!("Basic auth username and password cannot be empty"));
                        }
                    }
                    RemoteAuthConfig::OAuth { client_id, client_secret, .. } => {
                        if client_id.is_empty() || client_secret.is_empty() {
                            return Err(anyhow!("OAuth client_id and client_secret cannot be empty"));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    
    Ok(())
}

impl SimpleRouter {
    pub fn new(config: RouterConfig) -> Self {
        Self { 
            config,
            backend_manager: Arc::new(BackendManager::new()),
        }
    }
    
    /// Create a new router with a shared backend manager
    pub fn new_with_manager(config: RouterConfig, backend_manager: Arc<BackendManager>) -> Self {
        Self {
            config,
            backend_manager,
        }
    }
    
    /// Initialize all backend servers
    async fn initialize_backends(&self) -> Result<()> {
        info!("Initializing {} backend servers", self.config.servers.len());
        
        for server in &self.config.servers {
            match self.backend_manager.spawn_backend(server.clone()).await {
                Ok(_) => info!("✅ Spawned backend: {} ({})", server.name, server.id),
                Err(e) => error!("❌ Failed to spawn backend {}: {}", server.id, e),
            }
        }
        
        let status = self.backend_manager.get_status().await;
        let healthy_count = status.values().filter(|&&h| h).count();
        info!("Backend initialization complete: {}/{} healthy", healthy_count, status.len());
        
        if healthy_count == 0 && !self.config.servers.is_empty() {
            return Err(anyhow!("No healthy backends available"));
        }
        
        Ok(())
    }

    /// Run the router in stdio mode with backend routing
    pub async fn run(self) -> Result<()> {
        info!("Starting MCP router with {} configured servers", self.config.servers.len());
        
        // Initialize backends first
        self.initialize_backends().await?;
        
        // For now, just implement a basic stdio echo server
        // that demonstrates the router is working
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        
        // Send initialization response
        let init_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "0.1.0",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "JauAuth Router",
                    "version": "1.0.0"
                }
            }
        });
        
        stdout.write_all(format!("{}\n", init_response).as_bytes()).await?;
        stdout.flush().await?;
        
        // Read and handle messages
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) {
                        let response = self.handle_message(msg).await;
                        stdout.write_all(format!("{}\n", response).as_bytes()).await?;
                        stdout.flush().await?;
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading input: {}", e);
                    break;
                }
            }
        }
        
        // Shutdown all backends gracefully
        info!("Shutting down router...");
        if let Err(e) = self.backend_manager.shutdown_all().await {
            error!("Error during backend shutdown: {}", e);
        }
        
        Ok(())
    }
    
    async fn handle_message(&self, msg: serde_json::Value) -> serde_json::Value {
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = msg.get("id").cloned();
        
        let result = match method {
            "tools/list" => {
                // Get tools from all backends
                let backend_tools = self.backend_manager.get_all_tools().await;
                
                // Add our own router management tools
                let mut all_tools = vec![
                    serde_json::json!({
                        "name": "router:status",
                        "description": "Get router and backend status",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    }),
                    serde_json::json!({
                        "name": "router:list_servers",
                        "description": "List configured backend servers",
                        "inputSchema": {
                            "type": "object",
                            "properties": {}
                        }
                    }),
                ];
                
                // Add backend tools
                all_tools.extend(backend_tools);
                
                serde_json::json!({
                    "tools": all_tools
                })
            }
            
            "tools/call" => {
                let tool_name = msg.get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                    
                // Get arguments
                let arguments = msg.get("params")
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or(serde_json::json!({}));
                
                match tool_name {
                    "router:status" => {
                        let status = self.backend_manager.get_status().await;
                        let status_text: Vec<String> = status.iter()
                            .map(|(id, healthy)| format!("- {} ({}): {}", 
                                self.config.servers.iter().find(|s| &s.id == id).map(|s| &s.name).unwrap_or(&"Unknown".to_string()),
                                id, 
                                if *healthy { "✅ Healthy" } else { "❌ Unhealthy" }
                            ))
                            .collect();
                        
                        serde_json::json!({
                            "content": [{
                                "type": "text",
                                "text": format!("JauAuth Router Status:\n\nConfigured servers: {}\nHealthy backends: {}/{}\n\nBackend status:\n{}", 
                                    self.config.servers.len(),
                                    status.values().filter(|&&h| h).count(),
                                    status.len(),
                                    status_text.join("\n")
                                )
                            }]
                        })
                    }
                    
                    "router:list_servers" => {
                        let servers: Vec<_> = self.config.servers.iter()
                            .map(|s| {
                                let server_type = match s.r#type {
                                    ServerType::Local => format!("{}", s.command.as_deref().unwrap_or("<no command>")),
                                    ServerType::Remote => format!("{}", s.url.as_deref().unwrap_or("<no url>")),
                                };
                                format!("- {} ({}): {} [Type: {:?}, Sandbox: {:?}]", 
                                    s.name, s.id, server_type, s.r#type,
                                    match &s.sandbox.strategy {
                                        SandboxStrategy::None => "None",
                                        SandboxStrategy::Docker { .. } => "Docker",
                                        SandboxStrategy::Firejail { .. } => "Firejail",
                                        SandboxStrategy::Bubblewrap { .. } => "Bubblewrap",
                                        _ => "Other",
                                    }
                                )
                            })
                            .collect();
                            
                        serde_json::json!({
                            "content": [{
                                "type": "text",
                                "text": format!("Configured backend servers:\n{}", servers.join("\n"))
                            }]
                        })
                    }
                    
                    _ => {
                        // Route to backend
                        match self.backend_manager.route_tool_call(tool_name, arguments).await {
                            Ok(result) => result,
                            Err(e) => {
                                serde_json::json!({
                                    "error": {
                                        "code": -32603,
                                        "message": format!("Backend error: {}", e)
                                    }
                                })
                            }
                        }
                    }
                }
            }
            
            _ => {
                serde_json::json!({
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", method)
                    }
                })
            }
        };
        
        if let Some(id) = id {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            })
        } else {
            result
        }
    }
}

/// Load router configuration from a file
pub async fn load_config(path: &str) -> Result<RouterConfig> {
    let content = tokio::fs::read_to_string(path).await?;
    let config: RouterConfig = serde_json::from_str(&content)?;
    
    // Validate all server configurations
    for server in &config.servers {
        validate_server_config(server).await
            .map_err(|e| anyhow!("Invalid configuration for server '{}': {}", server.id, e))?;
    }
    
    Ok(config)
}