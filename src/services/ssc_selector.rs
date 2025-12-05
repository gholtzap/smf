use crate::types::{SscMode, SscModeConfig};

pub struct SscModeSelector {
    config: SscModeConfig,
}

impl SscModeSelector {
    pub fn new() -> Self {
        Self {
            config: SscModeConfig::default(),
        }
    }

    pub fn new_with_config(config: SscModeConfig) -> Self {
        Self { config }
    }

    pub fn select_ssc_mode(
        &self,
        requested_mode: Option<&str>,
        subscriber_allowed_modes: Option<&[SscMode]>,
        dnn_allowed_modes: Option<&[SscMode]>,
    ) -> Result<SscMode, String> {
        let mode = if let Some(req_mode_str) = requested_mode {
            let requested = SscMode::from_str(req_mode_str)
                .ok_or_else(|| format!("Invalid SSC mode requested: {}", req_mode_str))?;

            self.validate_mode(requested, subscriber_allowed_modes, dnn_allowed_modes)?;
            requested
        } else {
            self.get_default_mode(subscriber_allowed_modes, dnn_allowed_modes)
        };

        mode.validate()?;
        Ok(mode)
    }

    fn validate_mode(
        &self,
        mode: SscMode,
        subscriber_allowed_modes: Option<&[SscMode]>,
        dnn_allowed_modes: Option<&[SscMode]>,
    ) -> Result<(), String> {
        if !self.config.allowed_modes.contains(&mode) {
            return Err(format!(
                "SSC mode {} not allowed by network configuration",
                mode.as_str()
            ));
        }

        if let Some(subscriber_modes) = subscriber_allowed_modes {
            if !subscriber_modes.contains(&mode) {
                return Err(format!(
                    "SSC mode {} not allowed for subscriber",
                    mode.as_str()
                ));
            }
        }

        if let Some(dnn_modes) = dnn_allowed_modes {
            if !dnn_modes.contains(&mode) {
                return Err(format!(
                    "SSC mode {} not allowed for DNN",
                    mode.as_str()
                ));
            }
        }

        Ok(())
    }

    fn get_default_mode(
        &self,
        subscriber_allowed_modes: Option<&[SscMode]>,
        dnn_allowed_modes: Option<&[SscMode]>,
    ) -> SscMode {
        let default = self.config.default_mode;

        if let Some(subscriber_modes) = subscriber_allowed_modes {
            if !subscriber_modes.contains(&default) {
                if let Some(&first_allowed) = subscriber_modes.first() {
                    return first_allowed;
                }
            }
        }

        if let Some(dnn_modes) = dnn_allowed_modes {
            if !dnn_modes.contains(&default) {
                if let Some(&first_allowed) = dnn_modes.first() {
                    return first_allowed;
                }
            }
        }

        default
    }

    pub fn validate_ssc_mode(&self, mode: SscMode) -> Result<(), String> {
        if !self.config.allowed_modes.contains(&mode) {
            return Err(format!(
                "SSC mode {} not in allowed modes",
                mode.as_str()
            ));
        }
        mode.validate()
    }

    pub fn get_allowed_modes(&self) -> &[SscMode] {
        &self.config.allowed_modes
    }

    pub fn is_mode_allowed(&self, mode: SscMode) -> bool {
        self.config.allowed_modes.contains(&mode)
    }
}

impl Default for SscModeSelector {
    fn default() -> Self {
        Self::new()
    }
}
