use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Serialize, Deserialize};
use crate::types::RefToBinaryData;

pub enum AppError {
    DatabaseError(String),
    ValidationError(String),
    InternalError(String),
    NotFound(String),
}

impl AppError {
    pub fn cause_str(&self) -> &'static str {
        match self {
            AppError::DatabaseError(_) => "DB_ERROR",
            AppError::ValidationError(_) => "INVALID_REQUEST",
            AppError::InternalError(_) => "SYSTEM_FAILURE",
            AppError::NotFound(_) => "CONTEXT_NOT_FOUND",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            AppError::DatabaseError(_) => "Database Error",
            AppError::ValidationError(_) => "Bad Request",
            AppError::InternalError(_) => "Internal Server Error",
            AppError::NotFound(_) => "Not Found",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            AppError::DatabaseError(msg)
            | AppError::ValidationError(msg)
            | AppError::InternalError(msg)
            | AppError::NotFound(msg) => msg,
        }
    }

    pub fn to_problem_details(&self) -> serde_json::Value {
        serde_json::json!({
            "type": format!("https://httpstatuses.io/{}", self.status().as_u16()),
            "title": self.title(),
            "status": self.status().as_u16(),
            "detail": self.detail(),
            "cause": self.cause_str()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextCreateError {
    pub error: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_msg: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n2_sm_info: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_time: Option<String>,
}

impl SmContextCreateError {
    pub fn from_app_error(err: &AppError) -> Self {
        Self {
            error: err.to_problem_details(),
            n1_sm_msg: None,
            n2_sm_info: None,
            recovery_time: None,
        }
    }

    pub fn into_response(self, status: StatusCode) -> Response {
        (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            Json(self),
        ).into_response()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = self.to_problem_details();

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
