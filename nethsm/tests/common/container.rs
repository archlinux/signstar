use nethsm::Url;
use rustainers::{
    ExposedPort,
    ImageName,
    RunnableContainer,
    RunnableContainerBuilder,
    ToRunnableContainer,
    WaitStrategy,
};
use testresult::TestResult;
use uuid::{timestamp::Timestamp, NoContext, Uuid};

const IMAGE_NAME: &ImageName = &ImageName::new("docker.io/nitrokey/nethsm:testing");
const DEFAULT_PORT: u16 = 8443;
const DEFAULT_PATH: &str = "/api/v1";

#[derive(Debug)]
pub struct NetHsmImage {
    pub image: ImageName,
    pub port: ExposedPort,
}

impl NetHsmImage {
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
        Self {
            image: IMAGE_NAME.clone(),
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
            .with_wait_strategy(WaitStrategy::stderr_contains(
                "listening on 8443/TCP for HTTPS",
            ))
            .with_port_mappings([self.port.clone()])
            .build()
    }
}
