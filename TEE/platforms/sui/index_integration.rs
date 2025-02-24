use super::edge_integration::TEEClient;
use crate::core::error::TEEResult;

pub struct IndexTEEIntegration {
    tee_client: TEEClient,
}

impl IndexTEEIntegration {
    pub fn new(tee_endpoint: &str) -> Self {
        Self {
            tee_client: TEEClient::new(tee_endpoint),
        }
    }

    pub async fn private_data_indexing(
        &self,
        data_source: &str,
        query: &str,
        access_key: &[u8],
    ) -> TEEResult<Vec<u8>> {
        // Request TEE to perform private data indexing
        let result = self
            .tee_client
            .execute_function(
                "index_module",
                "private_query",
                vec![
                    data_source.as_bytes().to_vec(),
                    query.as_bytes().to_vec(),
                    access_key.to_vec(),
                ],
            )
            .await?;

        Ok(result)
    }
}
