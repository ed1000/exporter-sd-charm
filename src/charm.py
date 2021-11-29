#!/usr/bin/env python3

# pylint: disable=E0213

from ipaddress import ip_network
import logging
from typing import Optional
from urllib.parse import urlparse

from ops.main import main
from opslib.osm.charm import CharmedOsmBase
from opslib.osm.interfaces.http import HttpServer
from opslib.osm.pod import (
    ContainerV3Builder,
    IngressResourceV3Builder,
    PodRestartPolicy,
    PodSpecV3Builder,
)
from opslib.osm.validator import ModelValidator, validator


logger = logging.getLogger(__name__)

PORT = 8000


class ConfigModel(ModelValidator):
    lcm_password: str
    prometheus_password: str
    security_context: bool
    image_pull_policy: str
    max_file_size: int
    site_url: Optional[str]
    ingress_class: Optional[str]
    ingress_whitelist_source_range: Optional[str]
    tls_secret_name: Optional[str]

    @validator("image_pull_policy")
    def validate_image_pull_policy(cls, v):
        values = {
            "always": "Always",
            "ifnotpresent": "IfNotPresent",
            "never": "Never",
        }
        v = v.lower()
        if v not in values.keys():
            raise ValueError("value must be always, ifnotpresent or never")
        return values[v]

    @validator("max_file_size")
    def validate_max_file_size(cls, v):
        if v < 0:
            raise ValueError("value must be equal or greater than 0")
        return v

    @validator("site_url")
    def validate_site_url(cls, v):
        if v:
            parsed = urlparse(v)
            if not parsed.scheme.startswith("http"):
                raise ValueError("value must start with http")
        return v

    @validator("ingress_whitelist_source_range")
    def validate_ingress_whitelist_source_range(cls, v):
        if v:
            ip_network(v)
        return v


class ExporterSdCharmCharm(CharmedOsmBase):
    def __init__(self, *args):
        super().__init__(
            *args,
            oci_image="image",
        )

        self.service_discovery = HttpServer(self, "service-discovery")
        self.framework.observe(
            self.on["service-discovery"].relation_joined,
            self._publish_service_discovery_info,
        )

        self.register_targets = HttpServer(self, "register-targets")
        self.framework.observe(
            self.on["register-targets"].relation_joined,
            self._publish_register_targets_info,
        )

    def _publish_service_discovery_info(self, event):
        if self.unit.is_leader():
            config = ConfigModel(**dict(self.config))
            self.service_discovery.publish_info(
                host=self.app.name,
                port=PORT,
                path="/prometheus",
                basic_auth_username="prometheus",
                basic_auth_password=config.prometheus_password,
            )

    def _publish_register_targets_info(self, event):
        if self.unit.is_leader():
            config = ConfigModel(**dict(self.config))
            self.register_targets.publish_info(
                host=self.app.name,
                port=PORT,
                path="/exporters",
                basic_auth_username="lcm",
                basic_auth_password=config.lcm_password,
            )

    def build_pod_spec(self, image_info, **kwargs):
        # Validate config
        config = ConfigModel(**dict(self.config))

        # Create Builder for the PodSpec
        pod_spec_builder = PodSpecV3Builder(
            enable_security_context=config.security_context
        )
        container_builder = ContainerV3Builder(
            self.app.name,
            image_info,
            config.image_pull_policy,
            run_as_non_root=config.security_context,
        )

        exporter_sd_secret_name = f"{self.app.name}-exporter-sd-secret"
        pod_spec_builder.add_secret(
            exporter_sd_secret_name,
            {
                "lcm_password": config.lcm_password,
                "prometheus_password": config.prometheus_password,
            },
        )
        # Build Container
        container_builder.add_port(name=self.app.name, port=PORT)
        container_builder.add_secret_envs(
            secret_name=exporter_sd_secret_name,
            envs={
                "LCM_PASSWORD": "lcm_password",
                "PROMETHEUS_PASSWORD": "prometheus_password",
            },
        )

        container = container_builder.build()

        # Add container to pod spec
        pod_spec_builder.add_container(container)

        # Add Pod Restart Policy
        restart_policy = PodRestartPolicy()
        restart_policy.add_secrets(secret_names=(exporter_sd_secret_name,))
        pod_spec_builder.set_restart_policy(restart_policy)

        # Add ingress resources to pod spec if site url exists
        if config.site_url:
            parsed = urlparse(config.site_url)
            annotations = {
                "nginx.ingress.kubernetes.io/proxy-body-size": "{}".format(
                    str(config.max_file_size) + "m"
                    if config.max_file_size > 0
                    else config.max_file_size
                )
            }
            if config.ingress_class:
                annotations["kubernetes.io/ingress.class"] = config.ingress_class
            ingress_resource_builder = IngressResourceV3Builder(
                f"{self.app.name}-ingress", annotations
            )

            if config.ingress_whitelist_source_range:
                annotations[
                    "nginx.ingress.kubernetes.io/whitelist-source-range"
                ] = config.ingress_whitelist_source_range

            if parsed.scheme == "https":
                ingress_resource_builder.add_tls(
                    [parsed.hostname], config.tls_secret_name
                )
            else:
                annotations["nginx.ingress.kubernetes.io/ssl-redirect"] = "false"

            ingress_resource_builder.add_rule(parsed.hostname, self.app.name, PORT)
            ingress_resource = ingress_resource_builder.build()
            pod_spec_builder.add_ingress_resource(ingress_resource)
        return pod_spec_builder.build()


if __name__ == "__main__":
    main(ExporterSdCharmCharm)
