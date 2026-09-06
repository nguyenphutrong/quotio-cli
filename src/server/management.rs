use super::*;
use crate::accounts::{
    AccountError, api,
    oauth::{OAuthMode, SessionDto},
    vault::Vault,
};
use axum::http::HeaderMap;

fn vault(state: &ApiState) -> Result<Vault, ApiError> {
    state.vault.clone().ok_or(ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "account_storage_disabled",
    ))
}
pub(super) fn account_code(error: &AccountError) -> &'static str {
    match error {
        AccountError::Storage | AccountError::Corrupt => "credential_storage_unavailable",
        AccountError::Busy => "account_busy",
        AccountError::NotFound => "account_not_found",
        AccountError::Duplicate => "duplicate_account",
        AccountError::Label => "invalid_label",
        AccountError::Settings => "invalid_provider_settings",
        AccountError::NativeOAuth(_) => "native_login_required",
        AccountError::Unsupported => "unsupported_operation",
        AccountError::CallbackPort => "callback_port_unavailable",
        AccountError::OAuth => "oauth_failed",
        AccountError::Cancelled => "oauth_expired_or_cancelled",
        AccountError::Provider(_) => "credential_validation_failed",
        _ => "invalid_credential",
    }
}
fn account_error(error: AccountError) -> ApiError {
    let status = match error {
        AccountError::NotFound => StatusCode::NOT_FOUND,
        AccountError::Busy | AccountError::Duplicate | AccountError::CallbackPort => {
            StatusCode::CONFLICT
        }
        AccountError::Storage | AccountError::Corrupt => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    ApiError(status, account_code(&error))
}
pub(super) async fn list(State(state): State<Arc<ApiState>>) -> Result<Json<Value>, ApiError> {
    let accounts = tokio::time::timeout(Duration::from_secs(10), api::list(vault(&state)?))
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "account_busy"))?
        .map_err(account_error)?;
    Ok(Json(json!({"schema_version":1,"accounts":accounts})))
}
pub(super) async fn get_account(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<api::AccountDto>, ApiError> {
    Ok(Json(
        tokio::time::timeout(Duration::from_secs(10), api::get(vault(&state)?, id))
            .await
            .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "account_busy"))?
            .map_err(account_error)?,
    ))
}
pub(super) async fn usage(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let account = match get_account(State(state.clone()), Path(id.clone())).await {
        Ok(Json(a)) => a,
        Err(e) => return e.into_response(),
    };
    if !state
        .settings
        .read()
        .await
        .values
        .enabled_providers
        .iter()
        .any(|p| p == account.provider.id())
    {
        return error(StatusCode::NOT_FOUND, "provider_not_enabled");
    }
    super::usage_response(&state, Some(account.provider.id()), Some(&id)).await
}
enum Mutation {
    Create(api::ApiKeyInput),
    Update(String, api::AccountPatch),
    Remove(String),
}
pub(super) async fn create(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    let input = serde_json::from_value(body.clone())
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_request"))?;
    mutate(
        state,
        headers,
        "account_create",
        "",
        body,
        Mutation::Create(input),
    )
    .await
}
pub(super) async fn patch(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    let input = serde_json::from_value(body.clone())
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_request"))?;
    mutate(
        state,
        headers,
        "account_update",
        &id.clone(),
        body,
        Mutation::Update(id, input),
    )
    .await
}
pub(super) async fn remove(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    mutate(
        state,
        headers,
        "account_remove",
        &id.clone(),
        json!({}),
        Mutation::Remove(id),
    )
    .await
}
async fn mutate(
    state: Arc<ApiState>,
    headers: HeaderMap,
    kind: &str,
    target: &str,
    body: Value,
    mutation: Mutation,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    let vault = vault(&state)?;
    let mut keys = headers.get_all("idempotency-key").iter();
    let key = keys.next().and_then(|v| v.to_str().ok()).ok_or(ApiError(
        StatusCode::BAD_REQUEST,
        "idempotency_key_required",
    ))?;
    if keys.next().is_some() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_idempotency_key"));
    }
    let fingerprint = crate::cache::fingerprint(&[
        kind,
        target,
        &serde_json::to_string(&body)
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_request"))?,
    ]);
    drop(body);
    let (operation, new) = state
        .operations
        .lock()
        .await
        .start(kind, Some(key.into()), fingerprint)
        .map_err(operation_error)?;
    if new {
        let work = state.clone();
        let id = operation.id.clone();
        let spawn_result = state.spawn(async move {
            let result = async {
                match mutation {
                    Mutation::Create(input) => {
                        let prepared = api::prepare(&work.context, input)
                            .await
                            .map_err(|e| account_code(&e))?;
                        let _guard = crate::accounts::service::mutation_guard(&work.commit_guard)
                            .await
                            .map_err(|e| account_code(&e))?;
                        let account = api::save(vault, prepared)
                            .await
                            .map_err(|e| account_code(&e))?;
                        work.invalidate().await;
                        Ok(json!({"account_id":account.id}))
                    }
                    Mutation::Update(id, patch) => {
                        let _guard = crate::accounts::service::mutation_guard(&work.commit_guard)
                            .await
                            .map_err(|e| account_code(&e))?;
                        let account = api::update(vault, id, patch)
                            .await
                            .map_err(|e| account_code(&e))?;
                        work.invalidate().await;
                        Ok(json!({"account_id":account.id}))
                    }
                    Mutation::Remove(id) => {
                        let _guard = crate::accounts::service::mutation_guard(&work.commit_guard)
                            .await
                            .map_err(|e| account_code(&e))?;
                        api::remove(vault, id.clone())
                            .await
                            .map_err(|e| account_code(&e))?;
                        work.invalidate().await;
                        Ok(json!({"account_id":id}))
                    }
                }
            }
            .await;
            work.operations.lock().await.finish(&id, result);
        });
        if let Err(error) = spawn_result {
            state
                .operations
                .lock()
                .await
                .finish(&operation.id, Err("server_busy"));
            return Err(error);
        }
    }
    Ok((StatusCode::ACCEPTED, Json(operation)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionInput {
    provider: Provider,
    label: Option<String>,
    #[serde(default = "relay")]
    callback_mode: OAuthMode,
}
fn relay() -> OAuthMode {
    OAuthMode::Relay
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallbackInput {
    callback_url: String,
}
pub(super) async fn begin(
    State(state): State<Arc<ApiState>>,
    ApiJson(input): ApiJson<SessionInput>,
) -> Result<(StatusCode, Json<SessionDto>), ApiError> {
    if input.provider != Provider::Codex {
        return Err(ApiError(StatusCode::BAD_REQUEST, "native_login_required"));
    }
    let manager = state.oauth.as_ref().ok_or(ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "account_storage_disabled",
    ))?;
    Ok((
        StatusCode::CREATED,
        Json(
            manager
                .begin(input.label, input.callback_mode)
                .await
                .map_err(account_error)?,
        ),
    ))
}
pub(super) async fn session(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SessionDto>, ApiError> {
    let manager = state.oauth.as_ref().ok_or(ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "account_storage_disabled",
    ))?;
    let session = manager.get(&id).await.map_err(account_error)?;
    if session.status == crate::accounts::oauth::SessionStatus::Completed
        && state
            .snapshot
            .read()
            .await
            .as_ref()
            .is_none_or(|(g, _)| *g != state.generation.load(Ordering::SeqCst))
    {
        state.wake.notify_one();
    }
    Ok(Json(session))
}
pub(super) async fn cancel(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SessionDto>, ApiError> {
    let manager = state.oauth.as_ref().ok_or(ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "account_storage_disabled",
    ))?;
    Ok(Json(manager.cancel(&id).await.map_err(account_error)?))
}
pub(super) async fn callback(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<CallbackInput>,
) -> Result<Json<SessionDto>, ApiError> {
    let manager = state.oauth.clone().ok_or(ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "account_storage_disabled",
    ))?;
    // Continue token exchange/commit if the caller disconnects; polling reflects the actual result.
    let (send, receive) = tokio::sync::oneshot::channel();
    let work = state.clone();
    state.spawn(async move {
        let result = manager.callback(&id, &input.callback_url).await;
        work.wake.notify_one();
        let _ = send.send(result);
    })?;
    Ok(Json(
        receive
            .await
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?
            .map_err(account_error)?,
    ))
}

pub(super) async fn validate_refresh_account(
    state: &ApiState,
    provider: Provider,
    id: &str,
) -> Result<(), ApiError> {
    if id == "local" {
        return Ok(());
    }
    let account = tokio::time::timeout(Duration::from_secs(10), api::get(vault(state)?, id.into()))
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "account_busy"))?
        .map_err(account_error)?;
    if account.provider != provider {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_refresh_scope"));
    }
    Ok(())
}
