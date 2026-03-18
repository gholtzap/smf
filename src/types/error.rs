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

    pub fn from_app_error_with_reject(err: &AppError, pdu_session_id: u8) -> Self {
        use base64::{Engine as _, engine::general_purpose};
        use crate::types::nas::{NasParser, GsmCause};

        let cause = match err {
            AppError::ValidationError(msg) => {
                if msg.contains("DNN") || msg.contains("dnn") {
                    GsmCause::MissingOrUnknownDnn
                } else if msg.contains("PDU Session already exists") {
                    GsmCause::InvalidPduSessionIdentity
                } else if msg.contains("IP allocation") {
                    GsmCause::InsufficientResources
                } else if msg.contains("SSC") || msg.contains("ssc") {
                    GsmCause::NotSupportedSscMode
                } else if msg.contains("slice") || msg.contains("S-NSSAI") {
                    GsmCause::InsufficientResourcesForSlice
                } else {
                    GsmCause::RequestRejectedUnspecified
                }
            }
            AppError::DatabaseError(_) => GsmCause::InsufficientResources,
            AppError::InternalError(_) => GsmCause::NetworkFailure,
            AppError::NotFound(_) => GsmCause::RequestRejectedUnspecified,
        };

        let reject_msg = NasParser::build_pdu_session_establishment_reject(pdu_session_id, 0, cause);
        let encoded = general_purpose::STANDARD.encode(&reject_msg);

        Self {
            error: err.to_problem_details(),
            n1_sm_msg: Some(RefToBinaryData { content_id: encoded }),
            n2_sm_info: None,
            recovery_time: None,
        }
    }

    pub fn into_response(self, status: StatusCode) -> Response {
        (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextUpdateError {
    pub error: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_msg: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n2_sm_info: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_time: Option<String>,
}

impl SmContextUpdateError {
    pub fn from_app_error(err: &AppError) -> Self {
        Self {
            error: err.to_problem_details(),
            n1_sm_msg: None,
            n2_sm_info: None,
            recovery_time: None,
        }
    }

    pub fn from_app_error_with_reject(err: &AppError, pdu_session_id: u8, pti: u8) -> Self {
        use base64::{Engine as _, engine::general_purpose};
        use crate::types::nas::{NasParser, GsmCause};

        let cause = match err {
            AppError::ValidationError(msg) => {
                if msg.contains("message type") || msg.contains("NAS") {
                    GsmCause::MessageTypeNotCompatible
                } else if msg.contains("state") {
                    GsmCause::RequestRejectedUnspecified
                } else {
                    GsmCause::RequestRejectedUnspecified
                }
            }
            AppError::DatabaseError(_) => GsmCause::InsufficientResources,
            AppError::InternalError(_) => GsmCause::NetworkFailure,
            AppError::NotFound(_) => GsmCause::RequestRejectedUnspecified,
        };

        let reject_msg = NasParser::build_pdu_session_modification_reject(pdu_session_id, pti, cause);
        let encoded = general_purpose::STANDARD.encode(&reject_msg);

        Self {
            error: err.to_problem_details(),
            n1_sm_msg: Some(RefToBinaryData { content_id: encoded }),
            n2_sm_info: None,
            recovery_time: None,
        }
    }

    pub fn into_response(self, status: StatusCode) -> Response {
        (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(self),
        ).into_response()
    }
}
