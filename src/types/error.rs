use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};

pub enum AppError {
    DatabaseError(String),
    ValidationError(String),
    InternalError(String),
    NotFound(String),
}

impl AppError {
    fn cause_str(&self) -> &'static str {
        match self {
            AppError::DatabaseError(_) => "DB_ERROR",
            AppError::ValidationError(_) => "INVALID_REQUEST",
            AppError::InternalError(_) => "SYSTEM_FAILURE",
            AppError::NotFound(_) => "CONTEXT_NOT_FOUND",
        }
    }

    fn title(&self) -> &'static str {
        match self {
            AppError::DatabaseError(_) => "Database Error",
            AppError::ValidationError(_) => "Bad Request",
            AppError::InternalError(_) => "Internal Server Error",
            AppError::NotFound(_) => "Not Found",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, detail) = match &self {
            AppError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
        };

        let body = serde_json::json!({
            "type": "https://httpstatuses.io/".to_string() + &status.as_u16().to_string(),
            "title": self.title(),
            "status": status.as_u16(),
            "detail": detail,
            "cause": self.cause_str()
        });

        (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(body),
        ).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::InternalError(err.to_string())
    }
}
