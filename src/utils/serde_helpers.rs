use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serializer};

pub mod optional_datetime {
    use super::*;

    pub fn serialize<S>(dt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dt {
            Some(dt) => mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime::serialize(dt, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper(
            #[serde(deserialize_with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime::deserialize")]
            DateTime<Utc>,
        );

        Option::<Helper>::deserialize(deserializer).map(|opt| opt.map(|Helper(dt)| dt))
    }
}
