use crate::types::{SliceConfiguration, Snssai};

pub struct SliceSelector {
    configurations: Vec<SliceConfiguration>,
}

impl SliceSelector {
    pub fn new() -> Self {
        Self {
            configurations: SliceConfiguration::new_default(),
        }
    }

    pub fn new_with_config(configurations: Vec<SliceConfiguration>) -> Self {
        Self { configurations }
    }

    pub fn validate_snssai(&self, s_nssai: &Snssai) -> Result<&SliceConfiguration, String> {
        self.configurations
            .iter()
            .find(|config| config.matches(s_nssai) && config.allowed)
            .ok_or_else(|| {
                format!(
                    "S-NSSAI (SST: {}, SD: {:?}) is not allowed or not configured",
                    s_nssai.sst, s_nssai.sd
                )
            })
    }

    pub fn select_slice(
        &self,
        requested_snssai: &Snssai,
        allowed_snssais: Option<&[Snssai]>,
    ) -> Result<&SliceConfiguration, String> {
        if let Some(allowed) = allowed_snssais {
            if !allowed.iter().any(|s| {
                s.sst == requested_snssai.sst && s.sd == requested_snssai.sd
            }) {
                return Err(format!(
                    "Requested S-NSSAI (SST: {}, SD: {:?}) not in allowed list",
                    requested_snssai.sst, requested_snssai.sd
                ));
            }
        }

        self.validate_snssai(requested_snssai)
    }

    pub fn get_default_slice(&self) -> Option<&SliceConfiguration> {
        self.configurations
            .iter()
            .find(|config| config.s_nssai.sst == 1 && config.s_nssai.sd.is_none() && config.allowed)
    }

    pub fn list_allowed_slices(&self) -> Vec<&SliceConfiguration> {
        self.configurations
            .iter()
            .filter(|config| config.allowed)
            .collect()
    }

    pub fn get_slice_config(&self, s_nssai: &Snssai) -> Option<&SliceConfiguration> {
        self.configurations
            .iter()
            .find(|config| config.matches(s_nssai))
    }
}

impl Default for SliceSelector {
    fn default() -> Self {
        Self::new()
    }
}
