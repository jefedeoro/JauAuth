
//! HTTP API for MCP server communication

use axum::{
    extract::{State, Json},
    response::{IntoResponse, Response, sse::{Event, KeepAlive, Sse}},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use std::convert::Infallible;
use tokio::sync::RwLock;
use tokio_stream::Stream;
use tracing::{info, error, debug};

use crate::{
    simple_router::RouterConfig,
    backend_manager::BackendManager,
};

/// MCP API state
#[derive(Clone)]
pub struct McpApiState {
    pub router_config: Arc<RwLock<RouterConfig>>,
    pub backend_manager: Arc<BackendManager>,
}

/// Tool information
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Tool call request
#[derive(Debug, Deserialize)]
pub struct ToolCallRequest {
    pub tool: String,
    pub arguments: Value,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Tool call response
#[derive(Debug, Serialize)]
pub struct ToolCallResponse {
    pub result: Value,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

/// Get all available tools from backend servers
pub async fn list_tools(
    State(state): State<McpApiState>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let all_tools = state.backend_manager.get_all_tools().await;
    let backend_status = state.backend_manager.get_status().await;
    let config = state.router_config.read().await;

    // Build a map of server_id -> enabled status
    let enabled_servers: std::collections::HashMap<String, bool> = config.servers.iter()
        .map(|s| (s.id.clone(), s.enabled))
        .collect();

    let mut tools: Vec<ToolInfo> = Vec::new();

    // Process tools from all backends
    for tool_value in all_tools {
        if let Some(tool_obj) = tool_value.as_object() {
            if let Some(name) = tool_obj.get("name").and_then(|n| n.as_str()) {
                // Get server_id from tool name (format: server_id:tool_name)
                let server_id = name.split(':').next().unwrap_or("");

                // Only include tools from servers that are both enabled AND healthy
                let is_enabled = enabled_servers.get(server_id).copied().unwrap_or(true);
                let is_healthy = backend_status.get(server_id).copied().unwrap_or(false);

                if is_enabled && is_healthy {
                    tools.push(ToolInfo {
                        name: name.to_string(),
                        description: tool_obj.get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("No description")
                            .to_string(),
                        input_schema: tool_obj.get("inputSchema")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({
                                "type": "object",
                                "properties": {},
                                "required": []
                            })),
                    });
                }
            }
        }
    }

    Ok(Json(serde_json::json!({
        "tools": tools
    })))
}

/// Call a tool on a backend server
pub async fn call_tool(
    State(state): State<McpApiState>,
    Json(request): Json<ToolCallRequest>,
) -> Result<Json<ToolCallResponse>, ErrorResponse> {
    info!("MCP API: Calling tool {} (timeout: {:?}ms)", request.tool, request.timeout_ms);
    
    // Convert timeout_ms to Duration if provided
    let timeout = request.timeout_ms.map(Duration::from_millis);
    
    // Use async version if timeout is specified, otherwise use sync for backward compatibility
    let result = if timeout.is_some() {
        debug!("Using async tool call with timeout: {:?}", timeout);
        state.backend_manager.route_tool_call_async(&request.tool, request.arguments, timeout).await
    } else {
        debug!("Using synchronous tool call (no timeout specified)");
        state.backend_manager.route_tool_call(&request.tool, request.arguments).await
    };
    
    match result {
        Ok(result) => Ok(Json(ToolCallResponse { result })),
        Err(e) => {
            error!("Tool call failed: {}", e);
            Err(ErrorResponse {
                error: format!("Tool call failed: {}", e),
            })
        }
    }
}

/// Get router status
pub async fn get_status(
    State(state): State<McpApiState>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let config = state.router_config.read().await;
    let backend_status = state.backend_manager.get_status().await;

    let servers_status: Vec<serde_json::Value> = config.servers.iter().map(|server| {
        let healthy = backend_status.get(&server.id).copied().unwrap_or(false);
        serde_json::json!({
            "id": server.id,
            "name": server.name,
            "healthy": healthy,
            "command": server.command,
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "router": "healthy",
        "total_servers": config.servers.len(),
        "healthy_servers": backend_status.values().filter(|&&h| h).count(),
        "servers": servers_status,
    })))
}

/// List configured servers
pub async fn list_servers(
    State(state): State<McpApiState>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let config = state.router_config.read().await;
    let backend_status = state.backend_manager.get_status().await;

    let servers: Vec<serde_json::Value> = config.servers.iter().map(|server| {
        let healthy = backend_status.get(&server.id).copied().unwrap_or(false);
        serde_json::json!({
            "id": server.id,
            "name": server.name,
            "command": server.command,
            "args": server.args,
            "healthy": healthy,
            "requires_auth": server.requires_auth,
            "enabled": server.enabled,
            "tool_count": 0, // Will be filled by get_server_tool_count if needed
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "servers": servers
    })))
}

/// List tools for a specific server
pub async fn list_server_tools(
    State(state): State<McpApiState>,
    axum::extract::Path(server_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    info!("Listing tools for server: {}", server_id);

    let tools = state.backend_manager.get_server_tools(&server_id).await;

    if tools.is_empty() {
        // Check if server exists
        let config = state.router_config.read().await;
        if !config.servers.iter().any(|s| s.id == server_id) {
            return Err(ErrorResponse {
                error: format!("Server '{}' not found", server_id),
            });
        }
    }

    // Format tools with safe names
    let formatted_tools: Vec<serde_json::Value> = tools.iter().filter_map(|tool| {
        let tool_obj = tool.as_object()?;
        let name = tool_obj.get("name")?.as_str()?;
        let safe_name = name.replace(':', "_");
        Some(serde_json::json!({
            "name": safe_name,
            "original_name": name,
            "description": tool_obj.get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("No description"),
        }))
    }).collect();

    Ok(Json(serde_json::json!({
        "server_id": server_id,
        "tools": formatted_tools,
        "count": formatted_tools.len(),
    })))
}

/// Get tool schema by name
pub async fn get_tool_schema(
    State(state): State<McpApiState>,
    axum::extract::Path(tool_name): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    info!("Getting schema for tool: {}", tool_name);

    // Tool name format: server_id:tool_name or server_id_tool_name
    let normalized_name = if tool_name.contains(':') {
        tool_name.clone()
    } else {
        // Try to find the first underscore and treat it as separator
        tool_name.replacen('_', ":", 1)
    };

    let all_tools = state.backend_manager.get_all_tools().await;

    for tool_value in all_tools {
        if let Some(tool_obj) = tool_value.as_object() {
            if let Some(name) = tool_obj.get("name").and_then(|n| n.as_str()) {
                if name == normalized_name || name.replace(':', "_") == tool_name {
                    return Ok(Json(serde_json::json!({
                        "name": name,
                        "safe_name": name.replace(':', "_"),
                        "description": tool_obj.get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("No description"),
                        "inputSchema": tool_obj.get("inputSchema")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({
                                "type": "object",
                                "properties": {},
                                "required": []
                            })),
                    })));
                }
            }
        }
    }

    Err(ErrorResponse {
        error: format!("Tool '{}' not found", tool_name),
    })
}

/// Search query parameters
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub server_id: Option<String>,
}

/// Search tools by name or description
pub async fn search_tools(
    State(state): State<McpApiState>,
    axum::extract::Query(query): axum::extract::Query<SearchQuery>,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    info!("Searching tools: query='{}', server_id={:?}", query.q, query.server_id);

    let search_term = query.q.to_lowercase();
    let all_tools = state.backend_manager.get_all_tools().await;
    let backend_status = state.backend_manager.get_status().await;
    let config = state.router_config.read().await;

    // Build a map of server_id -> enabled status
    let enabled_servers: std::collections::HashMap<String, bool> = config.servers.iter()
        .map(|s| (s.id.clone(), s.enabled))
        .collect();

    let mut results: Vec<serde_json::Value> = Vec::new();

    for tool_value in all_tools {
        if let Some(tool_obj) = tool_value.as_object() {
            if let Some(name) = tool_obj.get("name").and_then(|n| n.as_str()) {
                // Extract server_id from tool name
                let server_id = name.split(':').next().unwrap_or("");

                // Filter by server_id if provided
                if let Some(ref filter_server) = query.server_id {
                    if server_id != filter_server {
                        continue;
                    }
                }

                // Only include tools from servers that are both enabled AND healthy
                let is_enabled = enabled_servers.get(server_id).copied().unwrap_or(true);
                let is_healthy = backend_status.get(server_id).copied().unwrap_or(false);
                if !is_enabled || !is_healthy {
                    continue;
                }

                let description = tool_obj.get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");

                // Match against name and description
                if name.to_lowercase().contains(&search_term) ||
                   description.to_lowercase().contains(&search_term) {
                    results.push(serde_json::json!({
                        "name": name.replace(':', "_"),
                        "original_name": name,
                        "server_id": server_id,
                        "description": description,
                        "match_type": if name.to_lowercase().contains(&search_term) {
                            "name"
                        } else {
                            "description"
                        }
                    }));
                }
            }
        }
    }

    Ok(Json(serde_json::json!({
        "query": query.q,
        "server_id_filter": query.server_id,
        "results": results,
        "count": results.len(),
    })))
}

/// SSE endpoint for ChatGPT - implements MCP SSE protocol
pub async fn sse_stream(
    State(state): State<McpApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    info!("MCP SSE connection established - sending tool list");

    // Get all tools upfront
    let all_tools = state.backend_manager.get_all_tools().await;
    let backend_status = state.backend_manager.get_status().await;
    let config = state.router_config.read().await;

    // Build a map of server_id -> enabled status
    let enabled_servers: std::collections::HashMap<String, bool> = config.servers.iter()
        .map(|s| (s.id.clone(), s.enabled))
        .collect();
    drop(config); // Release the read lock

    let mut tools = Vec::new();
    for tool_value in all_tools {
        if let Some(tool_obj) = tool_value.as_object() {
            if let Some(name) = tool_obj.get("name").and_then(|n| n.as_str()) {
                let server_id = name.split(':').next().unwrap_or("");

                // Only include tools from servers that are both enabled AND healthy
                let is_enabled = enabled_servers.get(server_id).copied().unwrap_or(true);
                let is_healthy = backend_status.get(server_id).copied().unwrap_or(false);

                if is_enabled && is_healthy {
                    // Format tool for MCP protocol
                    let mcp_tool = serde_json::json!({
                        "name": name,
                        "description": tool_obj.get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("No description"),
                        "input_schema": tool_obj.get("inputSchema")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({
                                "type": "object",
                                "properties": {},
                                "required": [],
                                "additionalProperties": false
                            }))
                    });
                    tools.push(mcp_tool);
                }
            }
        }
    }
    
    let tools_count = tools.len();
    let stream = async_stream::stream! {
        // Send initial tools list in MCP format
        let tools_response = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "result": {
                "tools": tools
            }
        });
        
        yield Ok(Event::default()
            .event("message")
            .data(tools_response.to_string()));
        
        info!("Sent {} tools to MCP client", tools_count);
        
        // Keep connection alive
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            // Send SSE comment to keep alive
            yield Ok(Event::default().comment("keep-alive"));
        }
    };
    
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Router for MCP API endpoints
pub fn mcp_api_routes() -> axum::Router<McpApiState> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/", get(sse_stream))  // SSE endpoint at /api/mcp for ChatGPT
        .route("/tools", get(list_tools))
        .route("/tools/search", get(search_tools))
        .route("/tools/{tool_name}/schema", get(get_tool_schema))
        .route("/tool/call", post(call_tool))
        .route("/status", get(get_status))
        .route("/servers", get(list_servers))
        .route("/servers/{server_id}/tools", get(list_server_tools))
}
