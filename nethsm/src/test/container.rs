use rust_dotenv::dotenv::DotEnv;
use rustainers::{
    ExposedPort,
    ImageName,
    RunnableContainer,
    RunnableContainerBuilder,
    ToRunnableContainer,
    WaitStrategy,
};
use testresult::TestResult;
use uuid::{NoContext, Uuid, timestamp::Timestamp};

use crate::Url;

/// The NetHSM container image without a specific tag
const IMAGE_NAME: &str = "docker.io/nitrokey/nethsm";
const DEFAULT_PORT: u16 = 8443;
const DEFAULT_PATH: &str = "/api/v1";

/// An image of NetHSM used to create a running container.
#[derive(Debug)]
pub struct NetHsmImage {
    /// Image name that is used to start the container.
    pub image: ImageName,

    /// Exposed port which will be used for communication with the NetHSM.
    pub port: ExposedPort,
}

impl NetHsmImage {
    /// Returns an base URL for the virtualized NetHSM.
    pub async fn url(&self) -> TestResult<Url> {
        Ok(Url::new(&format!(
            "https://localhost:{}{}",
            self.port.host_port().await?,
            DEFAULT_PATH
        ))?)
    }
}

impl Default for NetHsmImage {
    fn default() -> Self {
        let mut image = ImageName::new(IMAGE_NAME);
        image.set_tag(
            DotEnv::new("")
                .get_var("NETHSM_IMAGE_TAG".into())
                .unwrap_or_else(|| "testing".into()),
        );
        Self {
            image,
            port: ExposedPort::new(DEFAULT_PORT),
        }
    }
}

impl ToRunnableContainer for NetHsmImage {
    fn to_runnable(&self, builder: RunnableContainerBuilder) -> RunnableContainer {
        builder
            .with_image(self.image.clone())
            .with_container_name(Some(format!(
                "nethsm-test-{}",
                Uuid::new_v7(Timestamp::now(NoContext))
            )))
            .with_wait_strategy(WaitStrategy::HttpSuccess {
                https: true,
                require_valid_certs: false,
                path: "/".into(),
                container_port: 8443.into(),
            })
            .with_port_mappings([self.port.clone()])
            .build()
    }
}
