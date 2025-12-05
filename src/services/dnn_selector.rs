use crate::types::DnnConfiguration;

pub struct DnnSelector {
    configurations: Vec<DnnConfiguration>,
}

impl DnnSelector {
    pub fn new() -> Self {
        Self {
            configurations: DnnConfiguration::new_default(),
        }
    }

    pub fn new_with_config(configurations: Vec<DnnConfiguration>) -> Self {
        Self { configurations }
    }

    pub fn validate_dnn(&self, dnn: &str) -> Result<&DnnConfiguration, String> {
        self.configurations
            .iter()
            .find(|config| config.matches(dnn) && config.allowed)
            .ok_or_else(|| {
                format!(
                    "DNN '{}' is not allowed or not configured",
                    dnn
                )
            })
    }

    pub fn select_dnn(
        &self,
        requested_dnn: &str,
        allowed_dnns: Option<&[String]>,
    ) -> Result<&DnnConfiguration, String> {
        if let Some(allowed) = allowed_dnns {
            if !allowed.iter().any(|d| d == requested_dnn) {
                return Err(format!(
                    "Requested DNN '{}' not in allowed list",
                    requested_dnn
                ));
            }
        }

        self.validate_dnn(requested_dnn)
    }

    pub fn get_default_dnn(&self) -> Option<&DnnConfiguration> {
        self.configurations
            .iter()
            .find(|config| config.dnn == "internet" && config.allowed)
    }

    pub fn list_allowed_dnns(&self) -> Vec<&DnnConfiguration> {
        self.configurations
            .iter()
            .filter(|config| config.allowed)
            .collect()
    }

    pub fn get_dnn_config(&self, dnn: &str) -> Option<&DnnConfiguration> {
        self.configurations
            .iter()
            .find(|config| config.matches(dnn))
    }

    pub fn get_ip_pool_name(&self, dnn: &str) -> Option<String> {
        self.get_dnn_config(dnn).map(|config| config.ip_pool_name.clone())
    }
}

impl Default for DnnSelector {
    fn default() -> Self {
        Self::new()
    }
}
