use crate::models::RequestType;

pub struct EmergencyService;

impl EmergencyService {
    pub fn validate_emergency_request(
        request_type: &Option<RequestType>,
        dnn: &str,
        unauthenticated_supi: Option<bool>,
    ) -> Result<(), String> {
        let is_emergency = matches!(
            request_type,
            Some(RequestType::InitialEmergencyRequest) | Some(RequestType::ExistingEmergencyPduSession)
        );

        if !is_emergency {
            return Ok(());
        }

        Self::validate_emergency_dnn(dnn)?;

        if unauthenticated_supi == Some(true) {
            tracing::info!(
                "Emergency PDU session allowed for unauthenticated SUPI with DNN: {}",
                dnn
            );
        }

        Ok(())
    }

    fn validate_emergency_dnn(dnn: &str) -> Result<(), String> {
        let emergency_dnns = ["sos", "emergency", "ims-emergency"];

        if !emergency_dnns.contains(&dnn.to_lowercase().as_str()) {
            return Err(format!(
                "Emergency session requested but DNN '{}' is not an emergency DNN. Expected one of: {:?}",
                dnn, emergency_dnns
            ));
        }

        Ok(())
    }

    pub fn is_emergency_request(request_type: &Option<RequestType>) -> bool {
        matches!(
            request_type,
            Some(RequestType::InitialEmergencyRequest) | Some(RequestType::ExistingEmergencyPduSession)
        )
    }

    pub fn get_emergency_priority_5qi() -> u8 {
        5
    }

    pub fn should_bypass_authentication(
        is_emergency: bool,
        unauthenticated_supi: Option<bool>,
    ) -> bool {
        is_emergency && unauthenticated_supi == Some(true)
    }
}
